/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Content.Routing
* File: ProcessRoutine.cs 
*
* ProcessRoutine.cs is part of VNLib.Plugins.Essentials.Content.Routing which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Content.Routing is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Content.Routing is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

namespace VNLib.Plugins.Essentials.Content.Routing.Model
{
    public enum ProcessRoutine
    {
        Error           = FpRoutine.Error,
        Continue        = FpRoutine.Continue,
        Redirect        = FpRoutine.Redirect,
        Deny            = FpRoutine.Deny,      
        ServeOther      = FpRoutine.ServeOther,
        NotFound        = FpRoutine.NotFound,
        ServeOtherFQ    = FpRoutine.ServeOtherFQ,
        VirtualSkip     = FpRoutine.VirtualSkip, 
        Rewrite         = 50
    }
}
