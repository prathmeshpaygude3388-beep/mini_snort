from scapy.all import sniff


def start_sniffing(callback):
    """
    Starts live packet sniffing and forwards each packet
    to the callback function.
    """
    sniff(
        prn=callback,
        store=False
    )
