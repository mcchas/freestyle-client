import EventEmitter from "events";
import { fetch as undiciFetch, Agent } from 'undici'
import { CognitoClient, Session } from "./lib/cognito-client";
import * as Constants from "./constants";
import {
    Property,
    Home,
    Lock,
    LockStates
} from "./types";

class PubEmitter extends EventEmitter { };

export default class Freestyle {
    private username: string;
    private password: string;
    public session?: Session;
    private client: CognitoClient;
    private timer?: NodeJS.Timeout;
    public lock?: Lock;
    private home?: Home;
    private userPoolId: string = Constants.userPoolId;
    private userPoolClientId: string = Constants.userPoolClientId;
    private property?: Property;
    private emitter: PubEmitter;
    public watchFrequency: number = 25000;
    private agent: Agent;

    constructor(username: string, password: string) {
        this.username = username;
        this.password = password;
        this.client = new CognitoClient({
            userPoolId: this.userPoolId,
            userPoolClientId: this.userPoolClientId,
            clientSecret: Constants.clientSecret,
        })
        this.emitter = new PubEmitter();
        this.agent = new Agent({
            pipelining: 1,
            keepAliveTimeout: 30,
            keepAliveMaxTimeout: 600,
        })
    }

    async authenticate() {
        this.session = await this.client.authenticateUserSrp(this.username, this.password)
    }

    async authRefresh() {
        if (!this.session) {
            throw new Error('Missing session');
        }
        this.session = await this.client.refreshSession(this.session.refreshToken);
    }

    watch() {
        if (this.timer) {
            throw new Error("watch already running");
        }
        this.timer = setInterval(async () => {
            await this.poll().catch(e => console.error(e));
        }, this.watchFrequency);
    }

    set frequency(interval: number) {
        this.watchFrequency = interval;
        if (this.timer) {
            clearInterval(this.timer);
            this.timer = undefined;
            this.watch();
        }
    }

    async poll() {
        if (!this.session || !this.lock) {
            throw new Error('Missing session');
        }
        const lastLock = Object.assign({}, this.lock);
        await this.getHome();

        const changes = lockDiff(lastLock, this.lock);
        if (changes.length > 0) {
            this.emitter.emit('change', {
                previous: lastLock,
                changes: changes
            });
            changes.forEach((property: any) => {
                const key = Object.keys(property)[0];
                this.emitter.emit(key, property[key]);
            })
        }

        // check session expiry
        const timeNow = new Date().getTime();
        if (timeNow > (this.session.expiresIn - 60000 - this.watchFrequency)) {
            console.log('session expired, refreshing');
            await this.authRefresh();
        }
    }

    on(event: string, callback: Function) {
        this.emitter.on(event, (props) => {
            return callback(props);
        });

    }

    async getProperty(): Promise<Property> {
        if (!this.session) {
            throw new Error('Missing session');
        }
        const properties: Property[] = await this.apiGet(
            `${Constants.endpoint}/properties`
        )
        this.property = properties[0];
        return this.property;
    }

    async getHome(): Promise<Home> {
        if (!this.session || !this.property) {
            throw new Error('Missing session');
        }
        const home: Home = await this.apiGet(
            `${Constants.endpoint}/properties/${this.property.propertyId}`
        )
        this.home = home;
        this.lock = home.locks[0];
        return this.home;
    }

    async getHomeCb(callback: Function): Promise<void> {
        await this.getHome();
        callback();
    }

    printStatus() {
        if (!this.lock) {
            throw new Error('Missing lock data');
        }
        console.log(`lock ${this.lock.bleMac}:`)
        console.log(`  State: ${this.lock.reportedState}`)
        console.log(`  Desired State: ${this.lock.desiredState}`)
        console.log(`  Door: ${this.lock.doorClosed ? "Closed" : "Open"}`)
        console.log(`  Battery: ${this.lock.batteryPercent}%`)
        console.log("");
    }

    async init() {
        await this.authenticate();
        await this.getProperty()
        await this.getHome();
    }

    async unlock() {
        if (!this.session || !this.property || !this.lock) {
            throw new Error('Missing session');
        }
        return await this.apiPut(
            `${Constants.endpoint}/properties/${this.property.propertyId}/locks/${this.lock.bleMac}`,
            {
                desiredLockStateTimeoutSeconds: 12.0,
                desiredState: LockStates.UNLOCKED,
                desiredStateToken: {
                    data: 605271687314696
                }
            }
        )
    }

    async deadLock() {
        if (!this.session || !this.property || !this.lock) {
            throw new Error('Missing session');
        }
        return await this.apiPut(
            `${Constants.endpoint}/properties/${this.property.propertyId}/locks/${this.lock.bleMac}`,
            {
                desiredLockStateTimeoutSeconds: 12.0,
                desiredState: LockStates.LOCKED_DEADLOCK,
                desiredStateToken: {
                    data: 605271687314696
                }
            }
        )
    }

    async privacyLock() {
        if (!this.session || !this.property || !this.lock) {
            throw new Error('Missing session');
        }
        return await this.apiPut(
            `${Constants.endpoint}/properties/${this.property.propertyId}/locks/${this.lock.bleMac}`,
            {
                desiredLockStateTimeoutSeconds: 12.0,
                desiredState: LockStates.LOCKED_PRIVACY,
                desiredStateToken: {
                    data: 605271687314696
                }
            }
        );
    }

    private async apiGet<T>(url: string): Promise<T> {
        if (!this.session) {
            throw new Error('Missing session');
        }
        const response = await undiciFetch(url, {
            dispatcher: this.agent,
            headers: {
                'authorization': this.session.idToken,
                'user-agent': 'okhttp/4.9.3'
            },
            method: 'GET',
        });

        if (response && response.status < 300) {
            return response.json() as T;
        }

        const body = await response.json();
        return body as T;
    }

    private async apiPut<T>(url: string, data: any): Promise<T | undefined> {
        if (!this.session) {
            throw new Error('Missing session');
        }

        const response = await undiciFetch(url, {
            dispatcher: this.agent,
            headers: {
                'authorization': this.session.idToken,
                'user-agent': 'okhttp/4.9.3'
            },
            method: 'PUT',
            body: JSON.stringify(data)
        });

        if (response?.status == 204) {
            return response.status as T;
        }

        if (response && response.status < 300) {
            return response.json() as T;
        }

        const body = await response.json();
        return body as T;
    }

}

function lockDiff(a: Lock, b: Lock): Record<string, any> {
    const delta = [];
    if (a.bleMac !== b.bleMac) delta.push({ bleMac: b.bleMac });
    if (a.serial !== b.serial) delta.push({ serial: b.serial });
    if (a.displayName !== b.displayName) delta.push({ displayName: b.displayName });
    if (a.reportedState !== b.reportedState) delta.push({ reportedState: b.reportedState });
    if (a.desiredState !== b.desiredState) delta.push({ desiredState: b.desiredState });
    if (a.doorSensorDetected !== b.doorSensorDetected) delta.push({ doorSensorDetected: b.doorSensorDetected });
    if (a.autoRelockTimeSeconds !== b.autoRelockTimeSeconds) delta.push({ autoRelockTimeSeconds: b.autoRelockTimeSeconds });
    if (a.audioVolume !== b.audioVolume) delta.push({ audioVolume: b.audioVolume });
    if (a.resyncRequested !== b.resyncRequested) delta.push({ resyncRequested: b.resyncRequested });
    if (a.doorClosed !== b.doorClosed) delta.push({ doorClosed: b.doorClosed });
    if (a.tamperActive !== b.tamperActive) delta.push({ tamperActive: b.tamperActive });
    if (a.keypadLockoutActive !== b.keypadLockoutActive) delta.push({ keypadLockoutActive: b.keypadLockoutActive });
    if (a.batteryLow !== b.batteryLow) delta.push({ batteryLow: b.batteryLow });
    if (a.batteryPercent !== b.batteryPercent) delta.push({ batteryPercent: b.batteryPercent });
    if (a.lastSyncUnixTimestamp !== b.lastSyncUnixTimestamp) delta.push({ lastSyncUnixTimestamp: b.lastSyncUnixTimestamp });
    if (a.diagnosticEnabled !== b.diagnosticEnabled) delta.push({ diagnosticEnabled: b.diagnosticEnabled });
    if (a.firmwareVersion !== b.firmwareVersion) delta.push({ firmwareVersion: b.firmwareVersion });
    return delta;
}
