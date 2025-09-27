# Password_Generator
A terminal based password Generator

The program lets the user set a password the first time it's started.
The password is encrypted and stored in db. (BLOB)
The program also generates a encryption key.
The encryption key is also encrypted and stored in db. (BLOB SALT)

When a new password is generated, the user is prompteed to provide password lenght.
The password is then encrypted and stored in db. (cryptography.fernet)

The passwords can only be retrived if the correct user password is entered & correct db is targeted.
If the program is ran on a different computer, a new db will be created.
