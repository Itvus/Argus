"""Unit tests for cryptocurrency address extraction and block explorer mapping."""

from argus.modules.crypto_pivot import extract_crypto_wallets


def test_extract_crypto_wallets():
    """Verify regex extraction for Ethereum, Bitcoin, Solana, and ENS domains."""
    sample_texts = [
        "Donate ETH: 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 or vitalik.eth",
        "BTC address: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq or legacy 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "SOL tip jar: sol:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
        "Normal text without any wallets here.",
    ]
    details, leads = extract_crypto_wallets(sample_texts)
    networks = {d.network for d in details}
    assert "Ethereum" in networks
    assert "Bitcoin" in networks
    assert "ENS" in networks
    assert "Solana" in networks

    eth = next(d for d in details if d.network == "Ethereum")
    assert eth.address == "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    assert "etherscan.io" in eth.explorer_url

    ens = next(d for d in details if d.network == "ENS")
    assert ens.address == "vitalik.eth"

    btc = next(d for d in details if d.network == "Bitcoin")
    assert "mempool.space" in btc.explorer_url
