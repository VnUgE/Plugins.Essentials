import { describe, expect, it } from 'vitest';
import { SignJWT, importJWK } from 'jose';

import { useAccount, useAccountRpc, useMfaApi, useOtpApi, useOtpLogin } from '@vnuge/vnlib.browser'
import { vnlib, testUser } from '../../fixtures'

describe('OTP Login - E2E Tests', () => {

    const { login: normalLogin, logout } = useAccount(vnlib)
    const { getData: getAccStatus } = useAccountRpc(vnlib)
    const { sendRequest, getData: getMfaData } = useMfaApi(vnlib)
    const { addOrUpdate, removeKey } = useOtpApi({ sendRequest })
    const { login: otpLogin, isEnabled } = useOtpLogin({ config: vnlib })

    // Hardcoded test key pair for OTP login
    // Public key will be registered, private key will be used to sign JWTs
    const testKeyPair = {
        publicKey: {
            "kty": "EC",
            "x": "3Z6maPrq63mMYeooqkg5X45oqhC5T8W6uG8gH-8GpUg",
            "y": "O_y-s8ua3PAL0uRd4cs8uk7poB_mqugXDVAxGIs8JPI",
            "crv": "P-256",
            "kid": "otptestkey001",
            "alg": "ES256"
        },
        privateKey: {
            "kty": "EC",
            "x": "3Z6maPrq63mMYeooqkg5X45oqhC5T8W6uG8gH-8GpUg",
            "y": "O_y-s8ua3PAL0uRd4cs8uk7poB_mqugXDVAxGIs8JPI",
            "crv": "P-256",
            "d": "6IodwT4-bgfa1HZf5Xqb1GC5bhPkresTZma-TqvS76Y",
            "kid": "otptestkey001",
            "alg": "ES256"
        }
    }

    /**
     * Creates a signed JWT token for OTP login
     */
    const createOtpToken = async (username: string): Promise<string> => {
        const privateKey = await importJWK(testKeyPair.privateKey, testKeyPair.privateKey.alg)

        // Create JWT with required claims for OTP login
        // The server expects: sub (username), iat (issued at), nonce (random value)
        const jwt = await new SignJWT({
            sub: username,
            nonce: crypto.randomUUID(),  // Server needs a nonce for replay protection
            keyid: testKeyPair.privateKey.kid,
            serial: "abcdefghijklmnop"
        })
            .setProtectedHeader({
                alg: testKeyPair.privateKey.alg,
                kid: testKeyPair.privateKey.kid
            })
            .setIssuedAt()
            .setExpirationTime('5m')  // Short expiration for OTP
            .sign(privateKey)

        return jwt
    }

    describe('Before testing OTP login', () => {

        it('Logs the user in with normal credentials', async () => {
            const result = await normalLogin<any>(testUser)
            expect(result).toMatchObject({ code: 200, success: true })
        })

        it('Ensures the server supports OTP login', async () => {
            const { rpc_methods } = await getAccStatus()
            expect(isEnabled({ rpc_methods })).toBe(true)
        })

        it('Ensures the server supports pkotp for key management', async () => {
            const mfaData = await getMfaData()
            expect(mfaData).toMatchObject({ supported_methods: expect.arrayContaining(['pkotp']) })
        })
    })

    describe('When setting up OTP authentication', () => {

        it('Adds the test public key to the account', async () => {
            const result = await addOrUpdate(testKeyPair.publicKey, testUser)
            expect(result).toMatchObject({ code: 200, success: true })
        })

        it('Verifies the key was added successfully', async () => {
            const mfaData = await getMfaData()
            expect(mfaData).toMatchObject({
                methods: expect.arrayContaining([
                    expect.objectContaining({
                        type: 'pkotp',
                        enabled: true,
                        data: expect.objectContaining({
                            keys: expect.arrayContaining([
                                expect.objectContaining({
                                    kid: testKeyPair.publicKey.kid
                                })
                            ])
                        })
                    })
                ])
            })
        })

        it('Logs out to test OTP login', async () => {
            const result = await logout()
            expect(result).toMatchObject({ code: 200, success: true })
        })
    })

    describe('When logging in with OTP', () => {

        it('Successfully logs in using the OTP token', async () => {
            const otpToken = await createOtpToken(testUser.userName)
            expect(otpToken).toBeDefined()
            expect(otpToken).toBeTypeOf('string')
            expect(otpToken.split('.')).toHaveLength(3) // JWT has 3 parts

            const result = await otpLogin<any>(otpToken)

            expect(result).toMatchObject({
                success: true
            })
        })

        it('Verifies the user is authenticated after OTP login', async () => {
            const { status } = await getAccStatus()
            expect(status).toMatchObject({
                authenticated: true,
                is_local_account: true
            })
        })

        it('Removes the test public key from the account', async () => {
            const result = await removeKey(testKeyPair.publicKey, testUser)

            expect(result).toMatchObject({ code: 200, success: true })
        })

        it('Verifies the key was removed successfully', async () => {
            const mfaData = await getMfaData()
            const pkotpMethod = mfaData.methods.find(m => m.type === 'pkotp')

            // Either no pkotp method, or it has no keys
            if (pkotpMethod && 'data' in pkotpMethod) {
                const keys = (pkotpMethod.data as any).keys || []
                expect(keys.find((k: any) => k.kid === testKeyPair.publicKey.kid)).toBeUndefined()
            }
        })

        it('Logs out after testing OTP login', async () => {
            const result = await logout()
            expect(result).toMatchObject({ code: 200, success: true });
        })
    })
})
