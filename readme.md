# ghost 👻

A tiny transparent HTTPS reverse proxy that silently forwards your traffic. No bells, no whistles - just silent transmission.

## what it does
- Forwards HTTPS traffic
- Follows redirects
- Maintains a low profile
- Just works™

## what it doesn't do
- Store your data
- Modify your content
- Get in your way
- Try to be clever

## requirements
- OpenSSL (for the SSL stuff)
- libcurl (because reinventing wheels is tiresome)
- Your SSL certificate & key

## building
```bash
make
sudo make install
```

## running
```bash
sudo ./ghost  # needs root for port 443
```

## configuration
Edit these at the top of `ghost.c`:
```c
#define PORT      443
#define URL       "https://your-target-server.com"
#define CERT      "/path/to/your/cert.cer"
#define KEY       "/path/to/your/key.pem"
#define TARGETHOST "your-target-server.com"
```

## credits
Inspired by simplicity and the magic of transparent proxies.

## license
Do what you want with it. Just don't blame me if your ghosts misbehave.

## contributing
Found a bug? Want to improve something? PRs are welcome!

👻