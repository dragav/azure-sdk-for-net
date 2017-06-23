﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Microsoft.Azure.Management.ResourceManager;
using Microsoft.Azure.Management.Sql;
using Microsoft.Azure.Management.Sql.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Sql.Tests
{
    public class UsageScenarioTests
    {
        [Fact]
        public void TestGetUsageData()
        {
            string testPrefix = "sqlcrudtest-";
            string suiteName = this.GetType().FullName;
            SqlManagementTestUtilities.RunTestInNewV12Server(suiteName, "TestGetUsageData", testPrefix, (resClient, sqlClient, resourceGroup, server) =>
            {
                // Get server Usages
                IEnumerable<ServerUsage> serverUsages = sqlClient.Servers.ListUsages(resourceGroup.Name, server.Name);
                Assert.True(serverUsages.Count(s => s.ResourceName == server.Name) > 1);

                // Create a database and get usages
                string dbName = SqlManagementTestUtilities.GenerateName();
                var dbInput = new Database()
                {
                    Location = server.Location
                };
                sqlClient.Databases.CreateOrUpdate(resourceGroup.Name, server.Name, dbName, dbInput);
                IEnumerable<DatabaseUsage> databaseUsages = sqlClient.Databases.ListUsages(resourceGroup.Name, server.Name, dbName);
                Assert.True(databaseUsages.Where(db => db.ResourceName == dbName).Count() == 1);
            });
        }
    }
}
