/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: CoseEncodings.cs 
*
* CoseEncodings.cs is part of VNLib.Plugins.Essentials.Accounts which 
* is part of the larger VNLib collection of libraries and utilities.
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

namespace VNLib.Plugins.Essentials.Accounts.MFA
{
    internal static class CoseEncodings
    {
        public static int GetCodeFromAlg(string algName)
        {
            return algName switch
            {
                "ES256" => -7,
                "ES384" => -35,
                "ES512" => -36,
                _ => 0
            };
        }

        public static string GetAlgFromCode(int code)
        {
            return code switch
            {
                -7 => "ES256",
                -35 => "ES384",
                -36 => "ES512",
                _ => string.Empty
            };
        }

        public static string GetCurveFromCode(int code)
        {
            return code switch
            {
                -7 => "P-256",
                -35 => "P-384",
                -36 => "P-521",
                _ => string.Empty
            };
        }

        public static int GetPublicKeySizeForAlg(int code)
        {
            return code switch
            {
                -7 => 64,
                -35 => 96,
                -36 => 132,
                _ => -1
            };
        }
    }
}