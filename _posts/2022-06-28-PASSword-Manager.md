# PASS

## Installation

```
apt install -y pass gpg2
gpg2 --gen-key
gpg2 --full-gen-key

```

## Configuration
###  PASSWORD STORE

 * gpg2 --list-secret-keys
 * pass init GPG-KEY-ID
 
 ### PASSWORD MANAGEMENT
 
 * INSERT PWWD
	- pass insert Compras/amazon.com/pepe
	
* GENERATE PWWD 
	- pass generate Compras/aliexpress.com/pepe 35
* PASS EDIT
	- pass edit Compras/amazon.com/pepe
* PASS DELETE
	- pass rm Compras/amazon.com/pepe
* RETRIEVING PASSWORD
	(PLAIN TEXT)
	- pass Compras/amazon.com/pepe
	(CLIPBOARD)
	- pass -c Compras/amazon.com/pepe
	(SELECT ACCOUNT)
	- passmenu + dmenu

### PASSWORD STORE EXPORT

- gpg2 --export-secret-keys KEY-ID >> key-filename.gpg
- gpg2 --import key-filename.gpg
// Modify trustu level to ultimate
- gpg2 --edit-key KEY-ID

 