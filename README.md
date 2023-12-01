# Gainsborough Freestyle Tri Lock API client

## Constants

Cognito user pool, client ID and client secret were retrived from the Android APK.

##

At this time it only supports the first registered property and first lock for that property (as I only have 1 door).


## Example
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