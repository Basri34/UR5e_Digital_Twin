#!/usr/bin/env python3

import json

import cv2
import numpy as np
import rclpy
from cv_bridge import CvBridge, CvBridgeError
from rclpy.node import Node
from rclpy.qos import qos_profile_sensor_data
from sensor_msgs.msg import Image
from std_msgs.msg import String


CAMERA_TOPIC = "/sentinel/overhead_camera/image"
IMAGE_TOPIC = "/sentinel/object_detection/image"
DETECTION_TOPIC = "/sentinel/object_detection/detections"

MIN_AREA = 80.0
MAX_AREA = 10000.0
KERNEL = np.ones((3, 3), dtype=np.uint8)

COLOUR_RANGES = {
    "cube": [
        (np.array([95, 90, 60]), np.array([125, 255, 255]))
    ],
    "cylinder": [
        (np.array([3, 110, 70]), np.array([14, 255, 255])),
        (np.array([170, 110, 70]), np.array([179, 255, 255])),
    ],
}

DRAW_COLOURS = {
    "cube": (255, 0, 0),
    "cylinder": (0, 140, 255),
}


def blank_detection() -> dict:
    return {
        "detected": False,
        "centre_x": None,
        "centre_y": None,
        "x": None,
        "y": None,
        "width": None,
        "height": None,
        "area": None,
    }


class ObjectDetector(Node):
    def __init__(self) -> None:
        super().__init__("sentinel_object_detector")

        self.bridge = CvBridge()
        self.last_log_time = self.get_clock().now()

        self.create_subscription(
            Image,
            CAMERA_TOPIC,
            self.image_callback,
            qos_profile_sensor_data,
        )
        self.image_publisher = self.create_publisher(
            Image,
            IMAGE_TOPIC,
            qos_profile_sensor_data,
        )
        self.detection_publisher = self.create_publisher(
            String,
            DETECTION_TOPIC,
            10,
        )

        self.get_logger().info(f"Listening on {CAMERA_TOPIC}")

    def image_callback(self, message: Image) -> None:
        try:
            frame = self.bridge.imgmsg_to_cv2(message, "bgr8")
        except CvBridgeError as error:
            self.get_logger().error(f"Image conversion failed: {error}")
            return

        hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)
        detections = {
            name: self.detect(hsv, ranges)
            for name, ranges in COLOUR_RANGES.items()
        }

        annotated = frame.copy()
        for name, detection in detections.items():
            self.draw_detection(
                annotated,
                name.upper(),
                detection,
                DRAW_COLOURS[name],
            )

        self.draw_status(annotated, detections)
        self.publish_results(message, detections)
        self.publish_image(message, annotated)
        self.log_results(detections)

    @staticmethod
    def detect(hsv: np.ndarray, ranges: list[tuple[np.ndarray, np.ndarray]]) -> dict:
        mask = np.zeros(hsv.shape[:2], dtype=np.uint8)

        for lower, upper in ranges:
            mask |= cv2.inRange(
                hsv,
                lower.astype(np.uint8),
                upper.astype(np.uint8),
            )

        mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, KERNEL)
        mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, KERNEL, iterations=2)

        contours, _ = cv2.findContours(
            mask,
            cv2.RETR_EXTERNAL,
            cv2.CHAIN_APPROX_SIMPLE,
        )
        contours = [
            contour
            for contour in contours
            if MIN_AREA <= cv2.contourArea(contour) <= MAX_AREA
        ]

        if not contours:
            return blank_detection()

        contour = max(contours, key=cv2.contourArea)
        area = cv2.contourArea(contour)
        x, y, width, height = cv2.boundingRect(contour)
        moments = cv2.moments(contour)

        if moments["m00"]:
            centre_x = int(moments["m10"] / moments["m00"])
            centre_y = int(moments["m01"] / moments["m00"])
        else:
            centre_x = x + width // 2
            centre_y = y + height // 2

        return {
            "detected": True,
            "centre_x": centre_x,
            "centre_y": centre_y,
            "x": x,
            "y": y,
            "width": width,
            "height": height,
            "area": round(float(area), 2),
        }

    @staticmethod
    def draw_detection(
        image: np.ndarray,
        name: str,
        detection: dict,
        colour: tuple[int, int, int],
    ) -> None:
        if not detection["detected"]:
            return

        x = detection["x"]
        y = detection["y"]
        width = detection["width"]
        height = detection["height"]
        centre = (detection["centre_x"], detection["centre_y"])

        cv2.rectangle(image, (x, y), (x + width, y + height), colour, 2)
        cv2.circle(image, centre, 4, colour, -1)
        cv2.putText(
            image,
            f"{name} {centre}",
            (x, max(20, y - 8)),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.55,
            colour,
            2,
            cv2.LINE_AA,
        )

    @staticmethod
    def draw_status(image: np.ndarray, detections: dict[str, dict]) -> None:
        cv2.rectangle(image, (8, 8), (420, 68), (25, 25, 25), -1)

        for line, name in enumerate(("cube", "cylinder")):
            state = "DETECTED" if detections[name]["detected"] else "NOT DETECTED"
            cv2.putText(
                image,
                f"{name.upper()}: {state}",
                (18, 32 + line * 25),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.6,
                (255, 255, 255),
                2,
                cv2.LINE_AA,
            )

    def publish_results(self, source: Image, detections: dict[str, dict]) -> None:
        payload = {
            "stamp": {
                "sec": int(source.header.stamp.sec),
                "nanosec": int(source.header.stamp.nanosec),
            },
            "image_width": int(source.width),
            "image_height": int(source.height),
            **detections,
        }

        message = String()
        message.data = json.dumps(payload, separators=(",", ":"))
        self.detection_publisher.publish(message)

    def publish_image(self, source: Image, image: np.ndarray) -> None:
        try:
            message = self.bridge.cv2_to_imgmsg(image, "bgr8")
        except CvBridgeError as error:
            self.get_logger().error(f"Image conversion failed: {error}")
            return

        message.header = source.header
        self.image_publisher.publish(message)

    def log_results(self, detections: dict[str, dict]) -> None:
        now = self.get_clock().now()
        if (now - self.last_log_time).nanoseconds < 1_000_000_000:
            return

        statuses = []
        for name, detection in detections.items():
            if detection["detected"]:
                status = f"detected({detection['centre_x']},{detection['centre_y']})"
            else:
                status = "not_detected"
            statuses.append(f"{name}={status}")

        self.get_logger().info(" | ".join(statuses))
        self.last_log_time = now


def main(args=None) -> None:
    rclpy.init(args=args)
    node = ObjectDetector()

    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()


if __name__ == "__main__":
    main()