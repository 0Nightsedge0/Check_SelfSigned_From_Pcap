import pyshark
from OpenSSL import crypto


def is_self_signed(cert):
    issuer = cert.get_issuer()
    subject = cert.get_subject()
    return issuer == subject


def extract_certificates_from_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter='(ssl||tls) && ssl.handshake.type == 11')

    for packet in cap:
        #print(packet.tls.handshake_certificate)
        try:
            ip_src = packet.ip.src
            srcport = packet.tcp.srcport
            ip_dst = packet.ip.dst
            dstport = packet.tcp.dstport
            print(f"Source IP address: {ip_src}")
            print(f"Source Port: {srcport}")
            print(f"Destination IP address: {ip_dst}")
            print(f"Destination Port: {dstport}")
            cert_data = packet.tls.handshake_certificate
            cert_data = cert_data.replace(":", "")
            #print(cert_data)
            certificate_bytes = bytes.fromhex(cert_data)
            #print(certificate_bytes)
            cert = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate_bytes)
            if is_self_signed(cert):
                print("[!] Self-signed certificate!")
            else:
                print("[CA] Certificate issued by:", cert.get_issuer().commonName)
            print("Subject commonName:", cert.get_subject().commonName)
            print("Subject localityName:", cert.get_subject().localityName)
            print("Not Before:", cert.get_notBefore().decode())
        except Exception as e:
            print(f"Error extracting certificate: {e}")
        print("")

    return 0


def main():
    pcap_file = 'capture.pcap'
    extract_certificates_from_pcap(pcap_file)


if __name__ == "__main__":
    main()