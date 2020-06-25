using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace TokenManager
{
    public static class ExtensionMethods
    {
        #region Claims
        public static T GetValueFromClaim<T>(IEnumerable<Claim> claims, string type, T defaultValue = default(T))
        {
            T result = defaultValue;
            Claim claim = claims.FirstOrDefault(a =>
            a.Type.Equals(type, StringComparison.CurrentCultureIgnoreCase));
            if (claim != null)
            {
                return (T)Convert.ChangeType(claim.Value, typeof(T));
            }
            return result;
        }
        #endregion
    }
}
