/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: SocialMethodState.cs 
*
* SocialMethodState.cs is part of VNLib.Plugins.Essentials.Auth.Social which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Auth.Social is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Auth.Social is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/
using VNLib.Plugins.Essentials.Users;

namespace VNLib.Plugins.Essentials.Auth.Social.Controllers
{

    /// <summary>
    /// The state object for a social method call
    /// </summary>
    public sealed class SocialMethodState
    {
        /// <summary>
        /// The user manager for the server
        /// </summary>
        public IUserManager Users { get; internal init; } = null!;

        /// <summary>
        /// The connection entity that initiated the request
        /// </summary>
        public HttpEntity Entity { get; internal init; } = null!;

        /// <summary>
        /// The unique id of the method being called
        /// </summary>
        internal string MethodId { get; init; } = null!;

        /// <summary>
        /// Gets the stored secret data for the current method
        /// </summary>
        /// <returns>The secret data string stored from a previouse call to SetSecretData</returns>
        public string? GetPrivateData() 
            => Entity.Session[MethodId];

        /// <summary>
        /// Gets the stored private data for the current method
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <returns>The deserialized object representing the stored data if it exists</returns>
        public T? GetPrivateData<T>() where T : class 
            => UserEncodedData.Decode<T>(GetPrivateData());

        /// <summary>
        /// Sets the secret data for the current method
        /// </summary>
        /// <param name="secretData">Secret data to store for this method</param>
        public void SetSecretData(string? secretData) 
            => Entity.Session[MethodId] = secretData!;

        /// <summary>
        /// Sets the secret data for the current method as an object
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="secretData">The secret object to encode and store</param>
        public void SetSecretData<T>(T? secretData) where T : class 
            => SetSecretData(UserEncodedData.Encode(secretData));
    }
}
