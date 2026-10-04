import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="File watching and static analysis script.")

    parser.add_argument("-nh", "--num-hosts", type=str, required=True, help="The number of internal hosts running applications.")
    parser.add_argument("-ne", "--num-external", type=str, required=True, help="The number of regular external hosts to send traffic to the internal hosts.")
    parser.add_argument("-nm", "--num-malicious", type=str, required=True, help="The number of malicious external hosts to launch DoS attacks with.")

    args = parser.parse_args()
