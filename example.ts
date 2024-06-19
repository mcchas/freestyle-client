import Freestyle from "./dist";
import { emitKeypressEvents } from "readline";

const freestyle = new Freestyle("username@email.com", "password!");


async function main() {

    await freestyle.init()
    freestyle.printStatus();
    await freestyle.watch();

    freestyle.on('change', (data: any) => {
        console.log('change detected')
        console.log(data.changes);
    })

    freestyle.on('reportedState', (data: any) => {
        console.log('reported state changed to:', data)
    })

}

emitKeypressEvents(process.stdin);

if (process.stdin.isTTY)
    process.stdin.setRawMode(true);

console.log('press q to quit! (or: u, p, d, r)')
process.stdin.on('keypress', async (chunk, key) => {

    if (key && key.name == 'u') {
        console.log('unlocking');
        await freestyle.unlock();
    }

    if (key && key.name == 'p') {
        console.log('privacy locking');
        await freestyle.privacyLock();
    }

    if (key && key.name == 'd') {
        console.log('dead locking');
        await freestyle.deadLock();
    }

    if (key && key.name == 'r') {
        console.log('refreshing data');
        await freestyle.getHome();
        freestyle.printStatus();
    }

    if (key && key.name == 'q') {
        console.log('quit');
        process.exit(0);
    }

});


main();

