import { describe, expect, it } from 'vitest';

import {
  fidoMfaProcessor,
  totpMfaProcessor,
  useMfaLogin,
  type MfaLoginManager,
  isMfaLoginSupported,
  useAccountRpc
} from '@vnuge/vnlib.browser'
import { vnlib as config, vnlib } from '../../fixtures';

describe('MFA Login - e2e Tests', () => {

    const mfaLogin: MfaLoginManager = useMfaLogin(config, {
        handlers: [totpMfaProcessor(), fidoMfaProcessor()]
    })

    const { getData } = useAccountRpc(vnlib)

    describe('useMfaLogin server support', () => {
        
        it('Checks that the server supports mfa login', async () => {
            const data = await getData();
            expect(isMfaLoginSupported(data))
                .toBe(true)
        })

    })
})