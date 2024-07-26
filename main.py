import os
from collections import defaultdict
from decimal import Decimal

from openpyxl.workbook import Workbook

from dotenv import load_dotenv

from fetchers import get_block_transactions, connect_to_node
from output import create_transaction_details_sheet, create_transaction_hashes_sheet, create_address_statistics_sheet, \
    create_target_address_sheet
from processors import get_input_transactions

load_dotenv()


def analyze_block(rpc_connection, block_hash, output_file, target_address=None):
    transactions = get_block_transactions(rpc_connection, block_hash)
    input_tx_dict = get_input_transactions(rpc_connection, transactions)

    wb = Workbook()
    address_stats = defaultdict(lambda: {'balance_in': Decimal('0'), 'balance_out': Decimal('0'), 'tx_count': 0})
    unique_txs = set()
    target_address_txs = []

    create_transaction_details_sheet(wb, transactions, input_tx_dict, unique_txs, address_stats, target_address, target_address_txs)
    create_transaction_hashes_sheet(wb, transactions)
    create_address_statistics_sheet(wb, address_stats)
    create_target_address_sheet(wb, target_address, target_address_txs)

    wb.save(output_file)
    print(f"Excel file '{output_file}' has been created with the transaction details and statistics.")

def main():
    # Replace these with your actual RPC credentials and node information
    rpc_connection = connect_to_node()

    output_file = "block_transactions.xlsx"
    target_address = os.getenv('TARGET_ADDRESS')  # Add this to your .env file if you want to analyze a specific address

    analyze_block(rpc_connection, os.getenv('BLOCK_HASH', ''), output_file, target_address)


if __name__ == "__main__":
    main()
