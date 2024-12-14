import { describe, expect, it } from 'vitest';

import { fidoMfaProcessor, totpMfaProcessor, useMfaLogin } from '@vnuge/vnlib.browser'

const { isSupported } = useMfaLogin([
    totpMfaProcessor(),
    fidoMfaProcessor(),
])

describe('When a user wants to use multifactor authentication', () => {

    it('Ensures loaded processors are supported', async () => {
        expect(isSupported('fido')).toBe(true)
        expect(isSupported('totp')).toBe(true)
    })
})

