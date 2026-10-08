"""Manual RPC smoke check: run this file explicitly; pytest must stay offline."""
if __package__:
    from .monad_connection import connect_monad
else:
    from monad_connection import connect_monad


def main() -> None:
    w3 = connect_monad()
    block = w3.eth.get_block(w3.eth.block_number, full_transactions=True)
    print("Block number:", block["number"])
    print("Timestamp:", block["timestamp"])
    print("Transactions:", len(block["transactions"]))
    if block["transactions"]:
        tx = block["transactions"][0]
        print("Example transaction:")
        print("Hash:", tx["hash"].hex())
        print("From:", tx["from"])
        print("To:", tx["to"])
        print("Value:", w3.from_wei(tx["value"], "ether"))


if __name__ == "__main__":
    main()
