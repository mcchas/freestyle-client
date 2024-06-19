# Gainsborough Freestyle Tri Lock API client

## Constants

Cognito user pool, client ID and client secret were retrived from the Android APK.

##

At this time it only supports the first registered property and first lock for that property (as I only have 1 door).

## Example

Tested with node v20 (requires crypto).

```ts
import Freestyle from "freestyle-client";

const freestyle = new Freestyle("username@email.com", "password123");

// Authenticate
await freestyle.init()

// Watch for lock state changes
await freestyle.watch();

// Unlock the door
await freestyle.unlock();
    
```

## example.ts

Edit the username and password and run with ts-node
Use this to find your BLE mac address and offline AES key.

```sh
nvm use 20
npm install
npm i -g ts-node
ts-node ./example.ts
```

## Disclaimer

This is a reverse engineered project and is not affiliated with Gainsborough or Allegion.
