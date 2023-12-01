import hashJs from 'hash.js';
import { BigInteger } from 'jsbn';
import { Buffer } from 'buffer';
import formatInTimeZone from 'date-fns-tz/formatInTimeZone';

const initN =
  'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
  '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
  'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
  'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
  'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
  'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
  '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
  '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
  'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
  'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
  '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' +
  'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' +
  'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' +
  'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
  'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' +
  '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF';

const N = new BigInteger(initN, 16);
const g = new BigInteger('2', 16);
const k = new BigInteger(hashHexString(`${padHex(N)}${padHex(g)}`), 16);

export function padHex(bigInt: BigInteger): string {
  const HEX_MSB_REGEX = /^[89a-f]/i;
  const isNegative = bigInt.compareTo(BigInteger.ZERO) < 0;

  let hexStr = bigInt.abs().toString(16);
  hexStr = hexStr.length % 2 !== 0 ? `0${hexStr}` : hexStr;
  hexStr = HEX_MSB_REGEX.test(hexStr) ? `00${hexStr}` : hexStr;

  if (isNegative) {
    const invertedNibbles = hexStr
      .split('')
      .map(x => {
        const invertedNibble = ~parseInt(x, 16) & 0xf;
        return '0123456789ABCDEF'.charAt(invertedNibble);
      })
      .join('');

    const flippedBitsBI = new BigInteger(invertedNibbles, 16).add(BigInteger.ONE);
    hexStr = flippedBitsBI.toString(16);

    if (hexStr.toUpperCase().startsWith('FF8')) {
      hexStr = hexStr.substring(2);
    }
  }

  return hexStr;
}

export function hashHexString(str: string) {
  return hashBuffer(Buffer.from(str, 'hex'));
}

export function hashBuffer(buffer: Buffer) {
  const hash = hashJs.sha256().update(buffer).digest('hex');
  return new Array(64 - hash.length).join('0') + hash;
}

export async function generateSmallA() {
  return new BigInteger((await randomBytes(128)).toString('hex'), 16);
}

export function generateA(smallA: BigInteger) {
  const A = g.modPow(smallA, N);
  return A;
}

export function calculateU(A: BigInteger, B: BigInteger) {
  return new BigInteger(hashHexString(padHex(A) + padHex(B)), 16);
}

export function calculateS(X: BigInteger, B: BigInteger, U: BigInteger, smallA: BigInteger) {
  const gModPowXN = g.modPow(X, N);
  const bMinusKMult = B.subtract(k.multiply(gModPowXN));
  return bMinusKMult.modPow(smallA.add(U.multiply(X)), N).mod(N);
}

export function calculateHKDF(ikm: Buffer, salt: Buffer) {
  const infoBitsBuffer = Buffer.concat([
    Buffer.from('Caldera Derived Key', 'utf8'),
    Buffer.from(String.fromCharCode(1), 'utf8')
  ]);

  const prk = hashJs
    .hmac(hashJs.sha256 as any, salt)
    .update(ikm)
    .digest();
  const hmacResult = hashJs
    .hmac(hashJs.sha256 as any, prk)
    .update(infoBitsBuffer)
    .digest();

  return hmacResult.slice(0, 16);
}

export function getPasswordAuthenticationKey(
  poolName: string,
  username: string,
  password: string,
  B: BigInteger,
  U: BigInteger,
  smallA: BigInteger,
  salt: BigInteger
) {
  const usernamePassword = `${poolName}${username}:${password}`;
  const usernamePasswordHash = hashBuffer(Buffer.from(usernamePassword, 'utf-8'));
  const X = new BigInteger(hashHexString(padHex(salt) + usernamePasswordHash), 16);
  const S = calculateS(X, B, U, smallA);

  return calculateHKDF(Buffer.from(padHex(S), 'hex'), Buffer.from(padHex(U), 'hex'));
}

export function calculateSignature(
  poolName: string,
  userId: string,
  secretBlock: string,
  hkdf: number[],
  date = new Date()
) {
  const timeStamp = formatTimestamp(date);

  const concatBuffer = Buffer.concat([
    Buffer.from(poolName, 'utf8'),
    Buffer.from(userId, 'utf8'),
    Buffer.from(secretBlock, 'base64'),
    Buffer.from(timeStamp, 'utf8')
  ]);

  const signature = Buffer.from(
    hashJs
      .hmac(hashJs.sha256 as any, hkdf)
      .update(concatBuffer)
      .digest()
  ).toString('base64');

  return {
    signature,
    timeStamp
  };
}

export function decodeJwt<T = unknown>(jwt: string) {
  const [header, payload, signature] = jwt.split('.');
  return {
    header: JSON.parse(Buffer.from(header, 'base64').toString('utf-8')),
    payload: JSON.parse(Buffer.from(payload, 'base64').toString('utf-8')) as T,
    signature: signature
  };
}

export async function randomBytes(num: number) {
  let crypto: any = globalThis.crypto;
  if (!crypto) {
    const nodeCrypto = await import('node:crypto');
    crypto = nodeCrypto.webcrypto;
  }
  return Buffer.from(crypto.getRandomValues(new Uint8Array(num)));
}

export function formatTimestamp(date: Date) {
  return formatInTimeZone(date, 'UTC', "EEE MMM d HH:mm:ss 'UTC' yyyy");
}

export function calculateSecretHash(
  clientSecret: string,
  userPoolClientId: string,
  username: string
) {

  const message = `${username}${userPoolClientId}`;
  const hash = Buffer.from(
    hashJs
      .hmac(hashJs.sha256 as any, clientSecret)
      .update(message)
      .digest()
  ).toString('base64');

  return hash;
}