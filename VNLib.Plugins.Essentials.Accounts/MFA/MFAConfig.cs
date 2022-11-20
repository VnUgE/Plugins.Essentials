/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: MFAConfig.cs 
*
* MFAConfig.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Accounts is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Accounts is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System;
using System.Linq;
using System.Text.Json;
using System.Collections.Generic;

using VNLib.Hashing;
using VNLib.Utils.Extensions;

namespace VNLib.Plugins.Essentials.Accounts.MFA
{
    internal class MFAConfig
    {
        public byte[]? MFASecret { get; set; } = null;

        public bool TOTPEnabled { get; } = false;
        public string? IssuerName { get; }
        public TimeSpan TOTPPeriod { get; }
        public HashAlg TOTPAlg { get; }
        public int TOTPDigits { get; }
        public int TOTPSecretBytes { get; }
        public int TOTPTimeWindowSteps { get; }


        public bool FIDOEnabled { get; }
        public int FIDOChallangeSize { get; }
        public int FIDOTimeout { get; }
        public string? FIDOSiteName { get; }
        public string? FIDOAttestationType { get; }
        public FidoAuthenticatorSelection? FIDOAuthSelection { get; }

        public TimeSpan UpgradeValidFor { get; }
        public int NonceLenBytes { get; }

        public MFAConfig(IReadOnlyDictionary<string, JsonElement> conf)
        {
            UpgradeValidFor = conf["upgrade_expires_secs"].GetTimeSpan(TimeParseType.Seconds);
            NonceLenBytes = conf["nonce_size"].GetInt32();
            string siteName = conf["site_name"].GetString() ?? throw new KeyNotFoundException("Missing required key 'site_name' in 'mfa' config");

            //Totp setup
            if (conf.TryGetValue("totp", out JsonElement totpEl))
            {
                IReadOnlyDictionary<string, JsonElement> totp = totpEl.EnumerateObject().ToDictionary(k => k.Name, k => k.Value);

                //Get totp config
                IssuerName = siteName;
                //Get alg name
                string TOTPAlgName = totp["algorithm"].GetString()?.ToUpper() ?? throw new KeyNotFoundException("Missing required key 'algorithm' in plugin 'mfa' config");
                //Parse from enum string
                TOTPAlg = Enum.Parse<HashAlg>(TOTPAlgName);

               
                TOTPDigits = totp["digits"].GetInt32();
                TOTPPeriod = TimeSpan.FromSeconds(totp["period_secs"].GetInt32());
                TOTPSecretBytes = totp["secret_size"].GetInt32();
                TOTPTimeWindowSteps = totp["window_size"].GetInt32();
                //Set enabled flag
                TOTPEnabled = true;
            }
            //Fido setup
            if(conf.TryGetValue("fido", out JsonElement fidoEl))
            {
                IReadOnlyDictionary<string, JsonElement> fido = fidoEl.EnumerateObject().ToDictionary(k => k.Name, k => k.Value);
                FIDOChallangeSize = fido["challenge_size"].GetInt32();
                FIDOAttestationType = fido["attestation"].GetString();
                FIDOTimeout = fido["timeout"].GetInt32();
                FIDOSiteName = siteName;
                //Deserailze a 
                if(fido.TryGetValue("authenticatorSelection", out JsonElement authSel))
                {
                    FIDOAuthSelection = authSel.Deserialize<FidoAuthenticatorSelection>();
                }
                //Set enabled flag
                FIDOEnabled = true;
            }
        }
    }
}
