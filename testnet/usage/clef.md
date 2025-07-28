---
layout: doc
outline: deep
title: "Clef"
description: ""

---

# {{ $frontmatter.title}}


`clef` offers account management, supports remote interactions and automatic rules to approve/reject transaction signing requests all in a secure local environment. `clef` is also an external standalone backend signer for `gzond`.


Using `clef` for account management is considered best practice for `gzond` due to the additional security benefits it offers over using `gzond`'s built-in accounts module. 

This document includes step-by-step instructions for uses of `clef`, including using it as a standalone app and a backend signer for `gzond`.

:::info
Installation instructions for the clef system can be found in our [installation docs.](/testnet/install/install-clef) Head there to get started. You will have an executable for the QRL project Zond `clef` system following that guide. 
:::

## Initializing clef

`clef`'s entire storage is encrypted. To support encrypting data, the first step is to initialize `clef` with a random master seed that will be locked with a password:

```bash
clef --configdir <path-to-configdir> --suppress-bootwarn init
```

The masterseed file `masterseed.json` will be generated under the configdir provided.

:::details QRL Zond `clef` initialization output

Example:

```bash
mkdir clef-datadir
clef --suppress-bootwarn --configdir clef-datadir init 

The master seed of clef will be locked with a password.
Please specify a password. Do not forget this password!
Password:
Repeat password:

A master seed has been generated into clef-datadir/masterseed.json

This is required to be able to store credentials, such as:
* Passwords for keystores (used by rule engine)
* Storage for JavaScript auto-signing rules
* Hash of JavaScript rule-file

You should treat 'masterseed.json' with utmost secrecy and make a backup of it!
* The password is necessary but not enough, you need to back up the master seed too!
* The master seed does not contain your accounts, those need to be backed up separately!
```

Taking a look in the `masterseed.json` file:

```json
{
	"description":"Clef seed",
	"version":1,
	"params":{
		"cipher":"aes-128-ctr",
		"ciphertext":"a3636673bb9ccece04d2bff655aeabe9b70a35b79d9268ae7fa5fad6126273d880ef5331872916239713a51734fb55bed857dc3927db8337542e05a84b387bfb6e896b6cf1e202eabfea64e17f0c321fd60fbaa60c30627a76c5cb810cb611d60d2df0c1e02277e3d2ab04b5819922ea5bfa7b7252e54041b7f5056e820a008d37c4ed394ed1fb4c2f043a974789269fded18e887792a4465ffcc42202f7ad2dce3033d746721e5e259cd050a249d9387cf59bd608aa3c47f9be7301f751bd48c975c82f92aa77cfdf66034ea31e2a168cdfb3a87a9761ac9167ccf4e1039fecc249be79a11eed6afcb1a38cf7a270e1e90b9bc52ae8387a62e9c974ecd061cc",
		"cipherparams":{
			"iv":"3494b16c44aefec127edd9c3572e31fd"
		},
		"kdf":"scrypt",
		"kdfparams":{
			"dklen":32,
			"n":262144,
			"p":1,
			"r":8,
			"salt":"458a0741a7e12d3049adad91289a00097cc13614d56d1e84c4a01b06d7dbb879"
		},
		"mac":"e5484067f7196def2da1655b3a950b04c8a1e35b4981f0f66e4e4b6fe91262c6"
	}
}
```
:::

## Account Management

This module replaces `gzond`'s built-in account module.


### Create a new account

Use the `newaccount` command to add an account to the keystore. Pass the `--keystore` flag to indicate where to store the file.

```bash
clef --suppress-bootwarn --keystore <path-to-keystore> newaccount
```

The key will be generated under the keystore directory provided.

:::details Example `$ clef newaccount` Output

Example:

```bash
mkdir clef-keystore
clef --suppress-bootwarn --keystore clef-keystore newaccount

## New account password

Please enter a password for the new account to be created (attempt 0 of 3)
>
-----------------------
INFO [04-19|14:44:27.279] Your new key was generated               address=Z207354427f14C1ff531FF579d1ad799b406568b7
WARN [04-19|14:44:27.280] Please backup your key file!             path=/Users/qrluser/workspace/theQRL/go-zond/build/bin/clef-keystore/UTC--2025-04-19T10-44-26.377600000Z--Z207354427f14c1ff531ff579d1ad799b406568b7
WARN [04-19|14:44:27.280] Please remember your password!
Generated account Z207354427f14C1ff531FF579d1ad799b406568b7
```

Taking a look at the file created in the new keystore we see the following encrypted information:

```json
{
	"address":"Z2032c9dabfa5d5dac140fde0e72ec8d90962606d",
	"crypto":{
		"cipher":"aes-128-ctr",
		"ciphertext":"f21b0e4ffe59f53e509a80c40d4dfc31c073232a6f5cf2b89bd86cdbcefdbc73db76111df221fa23ce9608291f402c8c",
		"cipherparams":{
			"iv":"117fbbbf009107ba817c293d7aecc7c1"
		},
		"kdf":"scrypt",
		"kdfparams":{
			"dklen":32,
			"n":262144,
			"p":1,
			"r":8,
			"salt":"92ed0118ce8a79234a8aaefcf9818f670089c35f58c057a63f688f13ec29e3de"
		},
		"mac":"174c575aef647c22b264c28955b546c9683f74dca42e6144eed47582dba94853"
	},
	"id":"84e55393-031c-4a17-b8c6-e676819f55a2",
	"version":3
}

```
:::

### Import an account

```bash
clef --suppress-bootwarn --keystore <path-to-keystore> importraw <path-to-seed-file>
```

:::tip The seed must be 96 hex characters
:::


:::details Account Import example

Example:

First we need to have a secret key stored in a text file. We will echo the following seed into `seed.txt` to use for the example:

```bash
echo 60873ecdabe9de1ca784c9b6d9ca4773f7c5321138048bcb8115693779bbb6e20164e18c15049a84f8bac23896b94612 > seed.txt
```

Now, pass that key into the `clef` system:

```bash
$ clef --suppress-bootwarn --keystore clef-keystore importraw seed.txt

## Password

Please enter a password for the imported account
>
-----------------------
## Password

Please repeat the password you just entered
>
-----------------------
## Info
Key imported:
  Address Z207Cbd5169f730808c24d5BdD58c7185ED5deE47
  Keystore file: /Users/qrluser/workspace/theQRL/go-zond/build/bin/clef-keystore/UTC--2025-04-19T11-21-49.801406000Z--Z207cbd5169f730808c24d5bdd58c7185ed5dee47

The key is now encrypted; losing the password will result in permanently losing
access to the key and all associated funds!

Make sure to backup keystore and passwords in a safe location.
```
:::

### List accounts

View the accounts in the keystore.

```bash
clef --suppress-bootwarn --keystore <path-to-keystore> list-accounts
```
:::details List accounts example
Example:

```bash
clef --suppress-bootwarn --keystore clef-keystore list-accounts

Z207354427f14C1ff531FF579d1ad799b406568b7 (keystore:///Users/qrluser/workspace/theQRL/go-zond/build/bin/clef-keystore/UTC--2025-04-19T10-44-26.377600000Z--Z207354427f14c1ff531ff579d1ad799b406568b7)
Z207Cbd5169f730808c24d5BdD58c7185ED5deE47 (keystore:///Users/qrluser/workspace/theQRL/go-zond/build/bin/clef-keystore/UTC--2025-04-19T11-21-49.801406000Z--Z207cbd5169f730808c24d5bdd58c7185ed5dee47)
```
:::




## Automatic rules

For most users, manually confirming every transaction is the right way to use Clef because a human-in-the-loop can review every action. However, there are cases when it makes sense to set up some rules which permit Clef to sign a transaction without prompting the user.

This feature enables use cases like the following:

- auto-approve transactions with a specific recipient
- auto-approve transactions with a contract, with up to 0.05 ZND in value to maximum 1 ZND per 24h period
- auto-approve transactions to a contract with data=0xdeadbeef, if value=0 and gas < 44k
- auto-approve account listing


### Rules implementation

Rules are implemented as Javascript code in `.js` files.

The ruleset engine includes the methods `ApproveTx`, `ApproveListing` and `ApproveSignData`.

There are three possible outcomes from the ruleset engine that are handled in different ways:

| Return value                                           | Action               |
|--------------------------------------------------------|----------------------|
| "Approve"                                              | Auto-approve request |
| "Reject"                                               | Auto-reject request  |
| Anything else, pass decision to UI for manual approval |                      |

The steps required to run `clef` with an automated ruleset that requires account access are as follows:

#### Whitelist Example

A simple example is implementing a "whitelist" of recipients where transactions that have those accounts in the to field are automatically signed:

:::details 

##### 1. Define rules as Javascript and save as a .js file, e.g. `rules.js`

Create the `rules.js` file with the following content:

```js 
function ApproveTx(r) {
  if (r.transaction.to.toLowerCase() == 'zd4c4bb7d6889453c6c6ea3e9eab3c4177b4fbcc3') {
    return 'Approve';
  }
  // Otherwise goes to manual processing
}
```

##### 2. Calculate hash of the `rule.js` file

With the rule file complete, retrieve the `sha256sum` of the file:

```bash
sha256sum <path-to-rule-file>
```

Example:

```bash
sha256sumrules.js
ea06996262d8ba1445de556158d6909b7d875bf1ab3eb8c7af6869e8959d1272  rules.js
```

##### 3. Attest the rules in `clef`


```bash
clef --configdir <path-to-configdir> attest <hash-of-rule-file>
```

Example:

```bash
clef --suppress-bootwarn --configdir clef-datadir attest ea06996262d8ba1445de556158d6909b7d875bf1ab3eb8c7af6869e8959d1272

INFO [04-19|17:45:42.308] Ruleset attestation updated              sha256=ea06996262d8ba1445de556158d6909b7d875bf1ab3eb8c7af6869e8959d1272
```

##### 4. Set account password in `clef`


```bash
clef --suppress-bootwarn --configdir <path-to-configdir> setpw <address>
```

Example:

```bash
clef --suppress-bootwarn --configdir clef-datadir setpw Z207Cbd5169f730808c24d5BdD58c7185ED5deE47

Please enter a password to store for this address:
Password:
Repeat password:

Decrypt master seed of clef
Password:
INFO [04-19|17:55:55.397] Credential store updated                 set=Z207Cbd5169f730808c24d5BdD58c7185ED5deE47
```

:::





### Automatic Rule Examples

Below are some basic examples that give light to the power of automatic rules:

#### Allow destination


:::details
```js
function ApproveTx(r) {
  if (r.transaction.to.toLowerCase() == 'zd4c4bb7d6889453c6c6ea3e9eab3c4177b4fbcc3') {
    return 'Approve';
  }
  // Otherwise goes to manual processing
}
```
:::

#### Reject destination

:::details


```js
function ApproveTx(r) {
  if (r.transaction.to.toLowerCase() == 'zae967917c465db8578ca9024c205720b1a3651a9') {
    return 'Reject';
  }
  // Otherwise goes to manual processing
}
```
:::

#### Approve if value below limit

:::details

```js
function asBig(str) {
	if (str.slice(0, 2) == "0x") {
		return new BigNumber(str.slice(2), 16)
	}
	return new BigNumber(str)
}

function ApproveTx(req) {
	var limit = big.Newint("0xb1a2bc2ec50000")
	var value = asBig(req.transaction.value);

	if (req.transaction.to.toLowerCase() == "zxae967917c465db8578ca9024c205720b1a3651a9" && value.lt(limit)) {
		return "Approve"
	}
	// If we return "Reject", it will be rejected.
	// By not returning anything, the decision to approve/reject
	// will be passed to the next UI, for manual processing
}

function ApproveListing(req){
    if (req.metadata.scheme == "ipc"){ return "Approve"}
}
```
:::

#### Allow listing

:::details

```js
function ApproveListing() {
  return 'Approve';
}
```
:::

#### Rate-limited window

:::details

```js
function big(str) {
	if (str.slice(0, 2) == "0x") {
		return new BigNumber(str.slice(2), 16)
	}
	return new BigNumber(str)
}

// Time window: 1 week
var window = 1000* 3600*24*7;

// Limit: 1 ether
var limit = new BigNumber("1e18");

function isLimitOk(transaction) {
	var value = big(transaction.value)
	// Start of our window function
	var windowstart = new Date().getTime() - window;

	var txs = [];
	var stored = storage.get('txs');

	if (stored != "") {
		txs = JSON.parse(stored)
	}
	// First, remove all that has passed out of the time window
	var newtxs = txs.filter(function(tx){return tx.tstamp > windowstart});
	console.log(txs, newtxs.length);

	// Secondly, aggregate the current sum
	sum = new BigNumber(0)

	sum = newtxs.reduce(function(agg, tx){ return big(tx.value).plus(agg)}, sum);
	console.log("ApproveTx > Sum so far", sum);
	console.log("ApproveTx > Requested", value.toNumber());

	// Would we exceed the weekly limit ?
	return sum.plus(value).lt(limit)

}
function ApproveTx(r) {
	if (isLimitOk(r.transaction)) {
		return "Approve"
	}
	return "Nope"
}

/**
* OnApprovedTx(str) is called when a transaction has been approved and signed. The parameter
	* 'response_str' contains the return value that will be sent to the external caller.
* The return value from this method is ignore - the reason for having this callback is to allow the
* ruleset to keep track of approved transactions.
*
* When implementing rate-limited rules, this callback should be used.
* If a rule responds with neither 'Approve' nor 'Reject' - the tx goes to manual processing. If the user
* then accepts the transaction, this method will be called.
*
* TLDR; Use this method to keep track of signed transactions, instead of using the data in ApproveTx.
*/
function OnApprovedTx(resp) {
	var value = big(resp.tx.value)
	var txs = []
	// Load stored transactions
	var stored = storage.get('txs');
	if (stored != "") {
		txs = JSON.parse(stored)
	}
	// Add this to the storage
	txs.push({tstamp: new Date().getTime(), value: value});
	storage.put("txs", JSON.stringify(txs));
}
```
:::



## Gzond Integration

This section covers the steps necessary to set a `clef` agent as the backend signer for a `gzond` node. You can find a full step-by-step guide that includes remote interactions with the help of `gzond`'s javascript console in the [Manual Setup section](#manual-setup-with-automatic-rules).


### Start Clef Agent

Start a Clef agent using:

```bash
clef --suppress-bootwarn \
       --configdir <path-to-configdir> \
       --keystore <path-to-keystore> \
       --chainid <chainID> \
       --auditlog <path-to-audit-log> \
       --http
```

#### Start `clef` with Automatic Rules

Enable automatic rules by passing `--rules <path-to-rule-file>` at startup.

Example:

```bash
clef --suppress-bootwarn \ 
       --configdir clef-datadir \ 
       --keystore clef-keystore \ 
       --rules rules.js \
       --auditlog audit.log \
       --chainid 32382 \
       --http
```

Note: you might have to use a different `chainid`. The `rules.js` file should point to your `js` rules.

### Start Gzond node

Start a `gzond` node with the external signer enabled by passing `--signer=<path-to-clef.ipc>` at startup:

```bash {8}
gzond \
  --http \
  --http.api "zond,engine" \
  --datadir=<path-to-datadir> \
  --nodiscover \
  --syncmode=full \
  --ipcdisable \
  --signer <path-to-clef.ipc>
```

> *Additional startup flags may be needed. Refer to the running guide for more.*

Ignore the warning:

```bash
WARN [05-23|13:38:36.934] Failed to open wallet                    url=extapi://tmp/clef/clef.ipc err="operation not supported on external signers"
```


## Security Considerations

The password is necessary but not enough, you need to back up the master seed too; you should treat `masterseed.json` with utmost secrecy and make a backup of it.

:::warning Backup Accounts
The master seed does not contain your accounts, those need to be backed up separately!
:::



## Development

### Out-of-the-box Setup

#### Launch local testnet

Clone the `qrysm` repository and head to the testnet scripts directory:

```bash
git clone https://github.com/theQRL/qrysm && cd qrysm/scripts/local_testnet
```

Enable the remote signer fields in the network params file `network_params.yaml`:

```yml
use_remote_signer: true
remote_signer_type: clef
```

Launch the local testnet:

```bash
./start_local_testnet.sh
```

Note: stop the network after testing with:

```bash
./stop_local_testnet.sh
```


#### Remote interactions

Attach your terminal's standard input, output, and error to the `clef` container using the container's ID:

```bash
docker container attach <clef-container-id>`
```

Example: 

```bash
docker container attach signer-clef--f660cfeb1dfb42d1a55ffb345c4c3c42
```

Open a new terminal window and launch the javascript console in a `gzond` container:

```bash
docker exec -it <gzond-container-id> "gzond attach http://localhost:8545"
```

Example:

```bash
docker exec -it el-1-gzond-qrysm--9cc51228058f4e8485b01e8f6a1dbe66 sh -c "gzond attach http://localhost:8545"
```

This setup comes with a key pre-loaded in the keystore. Start by querying the accounts available:

```bash
zond.accounts
```

Go back to the `clef` terminal, approve this action and you should be able to see the following account in the JS console:

```bash
zond.accounts
["Z2018dcff6a42061e4203d3b8cbf48e9b890cbdf2"]
```

Create a transaction from the address above:

```bash
var tx = {from: 'Z2018DcfF6a42061E4203d3b8cbF48E9B890Cbdf2', to: 'Z201bdf510d5aa66d1b5db98dfb0f30d40b6ea47d', value: web3.toWei(0.1, 'ether')}
```

And send the transaction:

```bash
zond.sendTransaction(tx)
```

Approve the transaction in the `clef` terminal and input the account password 'passwordpassword'.

Wait for at least 60 seconds(slot) and confirm the recipient received the funds:

```bash
zond.getBalance('Z201bdf510d5aa66d1b5db98dfb0f30d40b6ea47d')
100000000000000000
```


### Manual Setup with automatic rules

#### Build from source

Create a temporary folder:

```bash
mkdir testnet && cd testnet
```

Clone dependencies:

```bash
git clone https://github.com/theQRL/qrysm
git clone https://github.com/theQRL/go-zond
```

Build binaries:

```bash
cd qrysm && go build -o=build/bin/beacon-chain ./cmd/beacon-chain
go build -o=build/bin/validator ./cmd/validator
go build -o=build/bin/qrysmctl ./cmd/qrysmctl
cd ..
cd go-zond && make all
cd ..
```


#### Clef steps

Create folders to store the `clef` keystore and config:

```bash
mkdir clef-keystore clef-config 
```

Save the following automatic rule as `rules.js`:

```js
function ApproveTx(req) {
	if (req.transaction.from.toLowerCase() == "z201bdf510d5aa66d1b5db98dfb0f30d40b6ea47d")  {
	return "Approve"
	}
    else{
        return "Reject"
    }
}

function ApproveListing(req){
    return "Approve"
}
```

and calculate the hash of the rule file:

```bash
sha256sum rules.js

7e8ebda5bd251a51d31377d4b4144e34f2d410fb12b701e831222e2e4825c8f2  rules.js
```

Init `clef` and input '1234567890' as the masterseed password:

```bash
go-zond/build/bin/clef --suppress-bootwarn --configdir clef-config init
```

Attest the rule in `clef` and input the masterseed password to decrypt it:

```bash
go-zond/build/bin/clef --suppress-bootwarn --configdir clef-config attest 7e8ebda5bd251a51d31377d4b4144e34f2d410fb12b701e831222e2e4825c8f2
```

Import an account and input the account password 'passwordpassword':

```bash
echo 89e5dc721ff0b98aac7f03f30763d54e31b8c773d6b98a8e81c73e78039897270fcbf94ae0f2422d294dbf17256e7051 > seed.txt

go-zond/build/bin/clef --suppress-bootwarn --keystore clef-keystore importraw seed.txt
```

Set the account password in `clef` for automatic signing by inputting the account password 'passwordpassword' and then '1234567890' to decrypt the master seed:

```bash
go-zond/build/bin/clef --suppress-bootwarn --configdir clef-config setpw Z201BdF510d5aa66d1b5DB98dFB0f30D40b6Ea47D
```

Run the `clef` agent and input the master seed password '123456789':

```bash
go-zond/build/bin/clef --suppress-bootwarn --configdir clef-config --keystore clef-keystore --rules rules.js --chainid 32382 --http
```

Ignore this log:

```bash
INFO [05-23|13:20:33.142] error occurred during execution          error="ReferenceError: OnSignerStartup is not defined at <eval>:1:16(5)"
```


#### Testnet steps


Open a new terminal window and store the following genesis as `genesis.json`:

:::details `genesis.json`

```json
{
	"config": {
		"chainId": 32382
	},
	"timestamp": "0x673c5362",
	"gasLimit": "0x1c9c380",
	"alloc": {
		"Z201bdf510d5aa66d1b5db98dfb0f30d40b6ea47d": {
			"balance": "0x1a784379d99db42000000"
		},
		"Z4242424242424242424242424242424242424242": {
			"code": "0x60806040526004361061003e575f3560e01c806301ffc9a714610042578063228951181461007e578063621fd1301461009a578063c5f2892f146100c4575b5f80fd5b34801561004d575f80fd5b5061006860048036038101906100639190610b67565b6100ee565b6040516100759190610bac565b60405180910390f35b61009860048036038101906100939190610c59565b6101bf565b005b3480156100a5575f80fd5b506100ae6105fb565b6040516100bb9190610da7565b60405180910390f35b3480156100cf575f80fd5b506100d861060d565b6040516100e59190610dd6565b60405180910390f35b5f7f01ffc9a7000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916827bffffffffffffffffffffffffffffffffffffffffffffffffffffffff191614806101b857507f85640907000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916827bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916145b9050919050565b610a208787905014610206576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016101fd90610e6f565b60405180910390fd5b6020858590501461024c576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161024390610efd565b60405180910390fd5b6111f38383905014610293576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161028a90610f8b565b60405180910390fd5b670de0b6b3a76400003410156102de576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016102d590611019565b60405180910390fd5b5f633b9aca00346102ef919061106d565b1461032f576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103269061110d565b60405180910390fd5b5f633b9aca00346103409190611158565b905067ffffffffffffffff801681111561038f576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610386906111f8565b60405180910390fd5b5f610399826107dd565b90507f649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c589898989858a8a6103ce6020546107dd565b6040516103e2989796959493929190611250565b60405180910390a15f60018a8a8a8a868b8b60405161040797969594939291906112ca565b602060405180830381855afa158015610422573d5f803e3d5ffd5b5050506040513d601f19601f820116820180604052508101906104459190611343565b9050838114610489576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161048090611404565b60405180910390fd5b6001602060026104999190611551565b6104a3919061159b565b602054106104e6576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016104dd9061163e565b60405180910390fd5b600160205f8282546104f8919061165c565b925050819055505f60205490505f5b60208110156105de5760018083160361053d57825f826020811061052e5761052d61168f565b5b018190555050505050506105f2565b60025f82602081106105525761055161168f565b5b0154846040516020016105669291906116dc565b6040516020818303038152906040526040516105829190611741565b602060405180830381855afa15801561059d573d5f803e3d5ffd5b5050506040513d601f19601f820116820180604052508101906105c09190611343565b92506002826105cf9190611158565b91508080600101915050610507565b505f6105ed576105ec611757565b5b505050505b50505050505050565b60606106086020546107dd565b905090565b5f805f60205490505f5b6020811015610757576001808316036106b45760025f826020811061063f5761063e61168f565b5b0154846040516020016106539291906116dc565b60405160208183030381529060405260405161066f9190611741565b602060405180830381855afa15801561068a573d5f803e3d5ffd5b5050506040513d601f19601f820116820180604052508101906106ad9190611343565b925061073b565b600283602183602081106106cb576106ca61168f565b5b01546040516020016106de9291906116dc565b6040516020818303038152906040526040516106fa9190611741565b602060405180830381855afa158015610715573d5f803e3d5ffd5b5050506040513d601f19601f820116820180604052508101906107389190611343565b92505b6002826107489190611158565b91508080600101915050610617565b506002826107666020546107dd565b5f60401b60405160200161077c939291906117cf565b6040516020818303038152906040526040516107989190611741565b602060405180830381855afa1580156107b3573d5f803e3d5ffd5b5050506040513d601f19601f820116820180604052508101906107d69190611343565b9250505090565b6060600867ffffffffffffffff8111156107fa576107f9611807565b5b6040519080825280601f01601f19166020018201604052801561082c5781602001600182028036833780820191505090505b5090505f8260c01b90508060076008811061084a5761084961168f565b5b1a60f81b825f815181106108615761086061168f565b5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191690815f1a905350806006600881106108a3576108a261168f565b5b1a60f81b826001815181106108bb576108ba61168f565b5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191690815f1a905350806005600881106108fd576108fc61168f565b5b1a60f81b826002815181106109155761091461168f565b5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191690815f1a905350806004600881106109575761095661168f565b5b1a60f81b8260038151811061096f5761096e61168f565b5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191690815f1a905350806003600881106109b1576109b061168f565b5b1a60f81b826004815181106109c9576109c861168f565b5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191690815f1a90535080600260088110610a0b57610a0a61168f565b5b1a60f81b82600581518110610a2357610a2261168f565b5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191690815f1a90535080600160088110610a6557610a6461168f565b5b1a60f81b82600681518110610a7d57610a7c61168f565b5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191690815f1a905350805f60088110610abe57610abd61168f565b5b1a60f81b82600781518110610ad657610ad561168f565b5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191690815f1a90535050919050565b5f80fd5b5f80fd5b5f7fffffffff0000000000000000000000000000000000000000000000000000000082169050919050565b610b4681610b12565b8114610b50575f80fd5b50565b5f81359050610b6181610b3d565b92915050565b5f60208284031215610b7c57610b7b610b0a565b5b5f610b8984828501610b53565b91505092915050565b5f8115159050919050565b610ba681610b92565b82525050565b5f602082019050610bbf5f830184610b9d565b92915050565b5f80fd5b5f80fd5b5f80fd5b5f8083601f840112610be657610be5610bc5565b5b8235905067ffffffffffffffff811115610c0357610c02610bc9565b5b602083019150836001820283011115610c1f57610c1e610bcd565b5b9250929050565b5f819050919050565b610c3881610c26565b8114610c42575f80fd5b50565b5f81359050610c5381610c2f565b92915050565b5f805f805f805f6080888a031215610c7457610c73610b0a565b5b5f88013567ffffffffffffffff811115610c9157610c90610b0e565b5b610c9d8a828b01610bd1565b9750975050602088013567ffffffffffffffff811115610cc057610cbf610b0e565b5b610ccc8a828b01610bd1565b9550955050604088013567ffffffffffffffff811115610cef57610cee610b0e565b5b610cfb8a828b01610bd1565b93509350506060610d0e8a828b01610c45565b91505092959891949750929550565b5f81519050919050565b5f82825260208201905092915050565b5f5b83811015610d54578082015181840152602081019050610d39565b5f8484015250505050565b5f601f19601f8301169050919050565b5f610d7982610d1d565b610d838185610d27565b9350610d93818560208601610d37565b610d9c81610d5f565b840191505092915050565b5f6020820190508181035f830152610dbf8184610d6f565b905092915050565b610dd081610c26565b82525050565b5f602082019050610de95f830184610dc7565b92915050565b5f82825260208201905092915050565b7f4465706f736974436f6e74726163743a20696e76616c6964207075626b6579205f8201527f6c656e6774680000000000000000000000000000000000000000000000000000602082015250565b5f610e59602683610def565b9150610e6482610dff565b604082019050919050565b5f6020820190508181035f830152610e8681610e4d565b9050919050565b7f4465706f736974436f6e74726163743a20696e76616c696420776974686472615f8201527f77616c5f63726564656e7469616c73206c656e67746800000000000000000000602082015250565b5f610ee7603683610def565b9150610ef282610e8d565b604082019050919050565b5f6020820190508181035f830152610f1481610edb565b9050919050565b7f4465706f736974436f6e74726163743a20696e76616c6964207369676e6174755f8201527f7265206c656e6774680000000000000000000000000000000000000000000000602082015250565b5f610f75602983610def565b9150610f8082610f1b565b604082019050919050565b5f6020820190508181035f830152610fa281610f69565b9050919050565b7f4465706f736974436f6e74726163743a206465706f7369742076616c756520745f8201527f6f6f206c6f770000000000000000000000000000000000000000000000000000602082015250565b5f611003602683610def565b915061100e82610fa9565b604082019050919050565b5f6020820190508181035f83015261103081610ff7565b9050919050565b5f819050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b5f61107782611037565b915061108283611037565b92508261109257611091611040565b5b828206905092915050565b7f4465706f736974436f6e74726163743a206465706f7369742076616c7565206e5f8201527f6f74206d756c7469706c65206f66206777656900000000000000000000000000602082015250565b5f6110f7603383610def565b91506111028261109d565b604082019050919050565b5f6020820190508181035f830152611124816110eb565b9050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f61116282611037565b915061116d83611037565b92508261117d5761117c611040565b5b828204905092915050565b7f4465706f736974436f6e74726163743a206465706f7369742076616c756520745f8201527f6f6f206869676800000000000000000000000000000000000000000000000000602082015250565b5f6111e2602783610def565b91506111ed82611188565b604082019050919050565b5f6020820190508181035f83015261120f816111d6565b9050919050565b828183375f83830152505050565b5f61122f8385610d27565b935061123c838584611216565b61124583610d5f565b840190509392505050565b5f60a0820190508181035f830152611269818a8c611224565b9050818103602083015261127e81888a611224565b905081810360408301526112928187610d6f565b905081810360608301526112a7818587611224565b905081810360808301526112bb8184610d6f565b90509998505050505050505050565b5f6080820190508181035f8301526112e381898b611224565b905081810360208301526112f8818789611224565b9050818103604083015261130c8186610d6f565b90508181036060830152611321818486611224565b905098975050505050505050565b5f8151905061133d81610c2f565b92915050565b5f6020828403121561135857611357610b0a565b5b5f6113658482850161132f565b91505092915050565b7f4465706f736974436f6e74726163743a207265636f6e737472756374656420445f8201527f65706f7369744461746120646f6573206e6f74206d6174636820737570706c6960208201527f6564206465706f7369745f646174615f726f6f74000000000000000000000000604082015250565b5f6113ee605483610def565b91506113f98261136e565b606082019050919050565b5f6020820190508181035f83015261141b816113e2565b9050919050565b5f8160011c9050919050565b5f808291508390505b6001851115611477578086048111156114535761145261112b565b5b60018516156114625780820291505b808102905061147085611422565b9450611437565b94509492505050565b5f8261148f576001905061154a565b8161149c575f905061154a565b81600181146114b257600281146114bc576114eb565b600191505061154a565b60ff8411156114ce576114cd61112b565b5b8360020a9150848211156114e5576114e461112b565b5b5061154a565b5060208310610133831016604e8410600b84101617156115205782820a90508381111561151b5761151a61112b565b5b61154a565b61152d848484600161142e565b925090508184048111156115445761154361112b565b5b81810290505b9392505050565b5f61155b82611037565b915061156683611037565b92506115937fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8484611480565b905092915050565b5f6115a582611037565b91506115b083611037565b92508282039050818111156115c8576115c761112b565b5b92915050565b7f4465706f736974436f6e74726163743a206d65726b6c6520747265652066756c5f8201527f6c00000000000000000000000000000000000000000000000000000000000000602082015250565b5f611628602183610def565b9150611633826115ce565b604082019050919050565b5f6020820190508181035f8301526116558161161c565b9050919050565b5f61166682611037565b915061167183611037565b92508282019050808211156116895761168861112b565b5b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52603260045260245ffd5b5f819050919050565b6116d66116d182610c26565b6116bc565b82525050565b5f6116e782856116c5565b6020820191506116f782846116c5565b6020820191508190509392505050565b5f81905092915050565b5f61171b82610d1d565b6117258185611707565b9350611735818560208601610d37565b80840191505092915050565b5f61174c8284611711565b915081905092915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52600160045260245ffd5b5f7fffffffffffffffffffffffffffffffffffffffffffffffff000000000000000082169050919050565b5f819050919050565b6117c96117c482611784565b6117af565b82525050565b5f6117da82866116c5565b6020820191506117ea8285611711565b91506117f682846117b8565b601882019150819050949350505050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffdfea2646970667358221220d50b8bcc63f95cdb172aa13e9a5ec51dc2f1ab189547eb65ddc4d2f80b175dec64736f6c637828302e382e32332d646576656c6f702e323032332e31312e382b636f6d6d69742e37393163303532310059",
			"balance": "0x0"
		}
	},
	"extraData": "0x426574614e65742c205a6f6e642c20584d53532c2044696c69746869756d2121",
	"number": "0x0",
	"gasUsed": "0x0",
	"parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
	"baseFeePerGas": null
}
```
:::

Store the qrysm config as `qrysm-config.yml`: 

```yml
CONFIG_NAME: interop
PRESET_BASE: interop

# Genesis
GENESIS_FORK_VERSION: 0x20000089

# Time parameters
SECONDS_PER_ETH1_BLOCK: 10
SECONDS_PER_SLOT: 10
SLOTS_PER_EPOCH: 6
ETH1_FOLLOW_DISTANCE: 8
EPOCHS_PER_ETH1_VOTING_PERIOD: 2

# Deposit contract
DEPOSIT_CONTRACT_ADDRESS: Z4242424242424242424242424242424242424242
```

Store the validator wallet password as `wallet_password.txt`: 

```bash
echo 12345678 > wallet_password.txt
```

Generate the genesis validators keys and input the keystore password '12345678': 

```bash
qrysm/build/bin/deposit \
  new-seed \
  --num-validators=64 \
  --folder validator_keys
```

Update the `--deposit-json-file` value with the path to the deposit data file available under the `validator_keys` folder generated in the previous step and generate the testnet resources:

```bash
qrysm/build/bin/qrysmctl testnet generate-genesis \
  --num-validators=64 \
  --gzond-genesis-json-in=genesis.json \
  --gzond-genesis-json-out=genesis.json \
  --output-ssz=genesis.ssz \
  --chain-config-file=qrysm-config.yml \
  --deposit-json-file=validator_keys/deposit_data-1745263318.json \
  --genesis-time=0 \
  --genesis-time-delay=300
```

Note: the network genesis time is 5 minutes away(genesis-time-delay=300); we must have all the network clients running before genesis time arrives.

Include the execution layer genesis:

```bash
go-zond/build/bin/gzond \
  --datadir=gzonddata1 \
  init \
  genesis.json
```

Run the `gzond` execution client with:

```bash
go-zond/build/bin/gzond \
  --http \
  --http.api "zond,engine" \
  --datadir=gzonddata1 \
  --nodiscover \
  --syncmode=full \
  --ipcdisable \
  --signer clef-config/clef.ipc
```

Ignore the warning:

```bash
WARN [04-21|20:47:53.398] Failed to open wallet                    url=extapi://clef-config/clef.ipc err="operation not supported on external signers"
```

Open a new terminal window and run the `qrysm` beacon node:

```bash
qrysm/build/bin/beacon-chain \
  --datadir=beacondata1 \
  --min-sync-peers=0 \
  --genesis-state=genesis.ssz \
  --bootstrap-node= \
  --chain-config-file=qrysm-config.yml \
  --config-file=qrysm-config.yml \
  --chain-id=32382 \
  --execution-endpoint=http://localhost:8551 \
  --accept-terms-of-use \
  --jwt-secret=gzonddata1/gzond/jwtsecret \
  --contract-deployment-block=0 \
  --suggested-fee-recipient=Z123463a4b065722e99115d6c222f267d9cabb524 \
  --enable-debug-rpc-endpoints
```

Open a new terminal window, create a validator wallet and input '12345678' as the wallet password:

```bash
qrysm/build/bin/validator wallet create --wallet-dir=qrysm-wallet-v2
```

Import the genesis validators keys into the validator wallet and input '12345678' for wallet password and keystore password:

```bash
qrysm/build/bin/validator accounts import --keys-dir=validator_keys --wallet-dir=qrysm-wallet-v2
```

and run the `qrysm` validator client:

```bash
qrysm/build/bin/validator \
  --datadir=validatordata1 \
  --accept-terms-of-use \
  --chain-config-file=qrysm-config.yml \
  --config-file=qrysm-config.yml \
  --wallet-dir=qrysm-wallet-v2 \
  --wallet-password-file=wallet_password.txt
```


#### Remote interactions 2

On a new terminal window, open the `gzond` console with:

```bash
go-zond/build/bin/gzond attach http://localhost:8545
```

By default, the user is required to manually confirm every action that touches account data, including querying accounts, signing and sending transactions but since we have pre-approved querying accounts and signing transactions in the rules file, the user won't have to manually confirm those actions.

List accounts with:

```js
zond.accounts
```

Create a transaction from the address above:

```js
var tx = {from: 'Z201bdf510d5aa66d1b5db98dfb0f30d40b6ea47d', to: 'Z201bdf510d5aa66d1b5db98dfb0f30d40b6ea50a', value: web3.toWei(0.1, 'ether')}
```

send the transaction:

```js
zond.sendTransaction(tx)
```

and the `clef` agent should log two auto approval messages(querying accounts and tx signing):

```bash
INFO [04-21|23:28:46.676] Op approved
INFO [04-21|23:29:02.286] Op approved
```

Ignore the warning:

```bash
INFO [04-21|23:29:02.754] error occurred during execution          error="ReferenceError: OnApprovedTx is not defined at <eval>:1:13(5)"
```

Wait for at least 60 seconds(slot) and confirm the recipient received the funds:
 
```js
zond.getBalance('Z201bdf510d5aa66d1b5db98dfb0f30d40b6ea50a')
100000000000000000
```