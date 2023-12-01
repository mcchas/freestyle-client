export enum LockStates {
    UNLOCKED = "UNLOCKED",
    LOCKED_PRIVACY = "LOCKED_PRIVACY",
    LOCKED_DEADLOCK = "LOCKED_DEADLOCK",
}

export enum Volume {
    LOW = "LOW",
    MEDIUM = "MEDIUM",
    HIGH = "HIGH",
}

export type Lock = {
    bleMac: string,
    serial: string,
    displayName: string,
    reportedState: LockStates,
    desiredState: LockStates | null,
    doorSensorDetected: boolean,
    autoRelockTimeSeconds: number,
    audioVolume: Volume,
    resyncRequested: boolean,
    doorClosed: boolean,
    tamperActive: boolean,
    keypadLockoutActive: boolean,
    batteryLow: boolean,
    batteryPercent: number,
    lastSyncUnixTimestamp: number,
    diagnosticEnabled: boolean,
    firmwareVersion: string;
}

export type Home = {
    propertyId: string,
    displayName: string,
    timezoneName: string,
    locks: Lock[];
    users: any[];
    gateways: any[];
    createdTimestamp: number,
    updatedTimestamp: number
}

export type Property = {
    propertyId: string,
    displayName: string,
}
