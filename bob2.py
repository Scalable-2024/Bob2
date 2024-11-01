import struct
import socket
import zlib

class Bob2Protocol:
    def __init__(self, version_major=0, version_minor=0):
        self.version_major = version_major
        self.version_minor = version_minor

    def build_message(self, message_type, dest_ipv6, dest_port, message_content):
        # Ensure IPv6 address is valid
        try:
            dest_ip_bytes = socket.inet_pton(socket.AF_INET6, dest_ipv6)
        except socket.error:
            raise ValueError("Invalid IPv6 address")

        # Message type and version
        header = struct.pack('!BBB', self.version_major, self.version_minor, message_type)

        # Destination address and port
        dest_port_bytes = struct.pack('!H', dest_port)

        # Message length (content only)
        message_length = len(message_content)
        if message_length > (1 << 40) - 1:  # Limit to 1TB
            raise ValueError("Message content exceeds maximum allowed size")

        # Length encoded in 5 bytes
        length_bytes = message_length.to_bytes(5, byteorder='big')

        # Calculate checksum of the message content
        checksum = zlib.crc32(message_content.encode('utf-8'))
        checksum_bytes = struct.pack('!I', checksum)

        # Assemble full message
        full_message = (header + dest_ip_bytes + dest_port_bytes +
                       length_bytes + checksum_bytes +
                       message_content.encode('utf-8'))
        return full_message

    def parse_message(self, raw_data):
        # Extract version, message type
        version_major, version_minor, message_type = struct.unpack('!BBB', raw_data[:3])

        # Extract destination IPv6 and port
        dest_ip_bytes = raw_data[3:19]
        dest_ipv6 = socket.inet_ntop(socket.AF_INET6, dest_ip_bytes)

        dest_port = struct.unpack('!H', raw_data[19:21])[0]

        # Extract message length
        message_length = int.from_bytes(raw_data[21:26], byteorder='big')

        # Extract and verify checksum
        expected_checksum = struct.unpack('!I', raw_data[26:30])[0]
        message_content = raw_data[30:30 + message_length]
        actual_checksum = zlib.crc32(message_content)

        if expected_checksum != actual_checksum:
            raise ValueError("Checksum verification failed")

        return {
            "version_major": version_major,
            "version_minor": version_minor,
            "message_type": message_type,
            "destination_ip": dest_ipv6,
            "destination_port": dest_port,
            "message_length": message_length,
            "checksum": expected_checksum,
            "message_content": message_content.decode('utf-8')
        }

if __name__ == "__main__":
    # Show example usage
    bob2 = Bob2Protocol()
    message = bob2.build_message(
        message_type=0,
        dest_ipv6="2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        dest_port=12345,
        message_content="Hello, LEO Satellite!"
    )

    parsed_message = bob2.parse_message(message)
    print(parsed_message)
