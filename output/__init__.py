from processors import process_coinbase_transaction, process_regular_transaction


def create_transaction_details_sheet(wb, transactions, input_tx_dict, unique_txs, address_stats, target_address, target_address_txs):
    ws1 = wb.active
    ws1.title = "Transaction Details"
    ws1.append(['Input Transaction', 'Input Index', 'Output Transaction', 'Output Index', 'Incoming Address',
                'Outgoing Address', 'Amount (satoshis)'])

    for tx in transactions:
        for vin_index, vin in enumerate(tx['vin']):
            if 'coinbase' in vin:
                process_coinbase_transaction(tx, vin_index, unique_txs, ws1, address_stats, target_address, target_address_txs)
            elif 'txid' in vin:
                process_regular_transaction(tx, vin, vin_index, input_tx_dict, unique_txs, ws1, address_stats, target_address, target_address_txs)


def create_transaction_hashes_sheet(wb, transactions):
    ws2 = wb.create_sheet(title="Transaction Hashes")
    ws2.append(['Transaction Hash'])
    for tx in transactions:
        ws2.append([tx['txid']])


def create_address_statistics_sheet(wb, address_stats):
    ws3 = wb.create_sheet(title="Address Statistics")
    ws3.append(['Address', 'Balance In (satoshis)', 'Balance Out (satoshis)', 'Number of Transactions'])
    for address, stats in address_stats.items():
        ws3.append([
            address,
            int(stats['balance_in']),
            int(stats['balance_out']),
            stats['tx_count']
        ])


def create_target_address_sheet(wb, target_address, target_address_txs):
    if target_address:
        ws4 = wb.create_sheet(title=f"Transactions for {target_address}")
        ws4.append(['Type', 'Transaction Hash', 'Index', 'Amount (satoshis)', 'Address'])
        for tx in target_address_txs:
            ws4.append([
                tx['type'],
                tx['txid'],
                tx.get('vin_index', tx.get('vout_index')),
                tx['amount'],
                tx['address']
            ])
