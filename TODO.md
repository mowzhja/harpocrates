- [x] add error handler code to cerberus for both client and server that sends error messages in case of an error
- [x] watch for the cipher.Nonce() usage !!
- [x] build a further wrapper for writing and reading in cerberus so that it checks the nonce at every message

- [ ] SWITCH BACK TO RUST? (tokio is pretty cool and concurrency in Go is not working (and i don't have enough time to fix the whole thing))

- [ ] add logging to both client and server (bookmarks)

- [ ] ? Add packet fragmentation => useless for now, but could be used to extend the functionality of harpocrates so that each fragment is sent over different networks, making it more resistent to interception and attack
