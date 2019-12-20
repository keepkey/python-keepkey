## Cosmos

Get your address:

```
keepkeyctl cosmos_get_address -d
```

Create unsigned transaction:

```
gaiacli tx send <destination_cosmosaccaddr> 1000uatom \
  --chain-id=<chain_id> \
  --from=<key_name> \
  --generate-only > unsigned.json
```

Sign the transaction:

```
keepkeyctl cosmos_sign_tx \
  --account-number=<account_number> \
  --sequence=<sequence> \
  -f unsigned.json > signed.json
```

Broadcast it:

```
gaiacli tx broadcast --node=<node> signed.json
```
