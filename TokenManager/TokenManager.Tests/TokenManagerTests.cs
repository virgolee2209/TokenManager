using System;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace TokenManager.Tests
{
    [TestClass]
    public class TokenManagerTests
    {
        private const string CLAIM_TYPE_USER_ID = "userId";
        private const string CLAIM_TYPE_RECORD_ID = "recordId";
        public string TestToken { get; set; }
        ClaimsPrincipal claimsPrincipal { get; set; }
        public string TestAudience { get { return "customAudienceId"; } }

        [TestInitialize]
        public void Setup()
        {
            claimsPrincipal = new ClaimsPrincipal();
            claimsPrincipal.AddIdentity(new ClaimsIdentity(new Claim[] {
                new Claim(CLAIM_TYPE_USER_ID, "9999"),
                new Claim(CLAIM_TYPE_RECORD_ID, "123456")
            })); ;

            TestToken = JwtHelper.GenerateToken(claimsPrincipal.Claims, TestAudience);
        }
        [TestMethod]
        public void TestValidateToken_Valid_NoTestAudience()
        {
            var result = JwtHelper.GetPrincipal(TestToken);
            Assert.IsNotNull(result);
            TestClaimPrincipal(result);
        }

        

        [TestMethod]
        public void TestValidateToken_Valid_TestAudience()
        {
            var result = JwtHelper.GetPrincipal(TestToken, TestAudience);
            Assert.IsNotNull(result);
            TestClaimPrincipal(result);
        }
        [TestMethod]
        public void TestValidateToken_Invalid_TestAudience()
        {
            var result = JwtHelper.GetPrincipal(TestToken, TestAudience + "changed to be invalid");
            Assert.IsNull(result);
        }
        [TestMethod]
        public void TestValidateToken_Invalid_TestExpiryTime()
        {
            int lifespanInSeconds = 10;
            TestToken = JwtHelper.GenerateToken(claimsPrincipal.Claims, TestAudience, lifespanInSeconds);
            Thread.Sleep(1000 * (lifespanInSeconds + 1));
            var result = JwtHelper.GetPrincipal(TestToken);
            Assert.IsNull(result);
        }

        private void TestClaimPrincipal(ClaimsPrincipal result)
        {
            //Assert.AreEqual(claimsPrincipal.Claims.Count(), result.Claims.Count());

            int originalValue = ExtensionMethods.GetValueFromClaim<int>(claimsPrincipal.Claims, CLAIM_TYPE_USER_ID);
            int resultValue = ExtensionMethods.GetValueFromClaim<int>(result.Claims, CLAIM_TYPE_USER_ID);
            Assert.AreEqual(originalValue, resultValue);

            originalValue = ExtensionMethods.GetValueFromClaim<int>(claimsPrincipal.Claims, CLAIM_TYPE_RECORD_ID);
            resultValue = ExtensionMethods.GetValueFromClaim<int>(result.Claims, CLAIM_TYPE_RECORD_ID);
            Assert.AreEqual(originalValue, resultValue);
        }
    }
}
