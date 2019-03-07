# Microsoft Graph .NET Authenttication Provider Library
Get started with Microsoft Graph .NET Authentication Provider Library by integrating Microsoft Graph API into your .Net application.
Microsoft Graph .NET Authentication Provider Library targets .NetStandard 1.3 and depends on [Microsoft.Identity.Client 2.7.1](https://www.nuget.org/packages/Microsoft.Identity.Client/2.7.1).
# Installation via NuGet
To install the authentication provider library via Nuget:
- Search for `Microsoft.Graph.Auth` in NuGet or 
- Type `Install-Package Microsoft.Graph.Auth` into the Package Manager Console.
# Getting Started
## 1. Register your application
Register your application to use Microsoft Graph API using one of the following
supported authentication portals:

* [Microsoft Application Registration Portal](https://apps.dev.microsoft.com):
  Register a new application that works with Microsoft Account and/or
  organizational accounts using the unified V2 Authentication Endpoint.
* [Microsoft Azure Active Directory](https://portal.azure.com): Register
  a new application in your tenant's Active Directory to support work or school
  users for your tenant or multiple tenants.

## 2. Create IAuthenticationProvider object
### 2.1. Confidential Client Providers
#### a. Authorization code provider
```csharp
ConfidentialClientApplication clientApplication = AuthorizationCodeProvider.CreateClientApplication(clientId, redirectUri, clientCredential);
AuthorizationCodeProvider authenticationProvider = new AuthorizationCodeProvider(clientApplication, scopes);
```
#### b. Client credential provider
```csharp
ConfidentialClientApplication clientApplication = ClientCredentialProvider.CreateClientApplication(clientId, redirectUri, clientCredential);
ClientCredentialProvider authenticationProvider = new ClientCredentialProvider(clientApplication);
```
#### c. On behalf of provider
```csharp
ConfidentialClientApplication clientApplication = OnBehalfOfProvider.CreateClientApplication(clientId, redirectUri, clientCredential);
OnBehalfOfProvider authenticationProvider = new OnBehalfOfProvider(clientApplication, scopes);
```
### 2.2. Public Client Providers
#### a. Device code provider
```csharp
PublicClientApplication clientApplication = DeviceCodeProvider.CreateClientApplication(clientId);
DeviceCodeProvider authenticationProvider = new DeviceCodeProvider(clientApplication, scopes);
```
#### b. Integrated windows authentication provider
```csharp
PublicClientApplication clientApplication = IntegratedWindowsAuthenticationProvider.CreateClientApplication(clientId);
IntegratedWindowsAuthenticationProvider authenticationProvider = new IntegratedWindowsAuthenticationProvider(clientApplication, scopes);
```
#### c. Interactive authentication provider
```csharp
PublicClientApplication clientApplication = InteractiveAuthenticationProvider.CreateClientApplication(clientId);
InteractiveAuthenticationProvider authenticationProvider = new InteractiveAuthenticationProvider(clientApplication, scopes);
```
#### d. Username password provider
```csharp
PublicClientApplication clientApplication = UsernamePasswordProvider.CreateClientApplication(clientId);
UsernamePasswordProvider authenticationProvider = new UsernamePasswordProvider(clientApplication, scopes);
```

## 3. Initialize Microsoft Graph service client with an authentication provider
```csharp
GraphServiceClient graphServiceClient = new GraphServiceClient(authenticationProvider);
```
## 4. Make request to Microsoft Graph
Once the GraphServiceClient has been initialized with an authentication provider, you can make calls against Microsoft Graph service. The requests should follow the [Microsoft Graph REST API](https://docs.microsoft.com/en-us/graph/overview) syntax.

For example, to retrieve a user's default drive:

```csharp
GraphServiceClient graphServiceClient = new GraphServiceClient(authenticationProvider);
var drive = await graphServiceClient.Me.Drive.Request().GetAsync();
```
# Example
## 1. Client credential provider
```csharp
ConfidentialClientApplication clientApplication = ClientCredentialProvider.CreateClientApplication(clientId, redirectUri, clientCredential);
ClientCredentialProvider authenticationProvider = new ClientCredentialProvider(clientApplication);

GraphServiceClient graphServiceClient = new GraphServiceClient(authenticationProvider);
var me = await graphServiceClient.Me.Request().WithForceRefresh(true).GetAsync();
```

# Issues
To view or log issues, see [issues](https://github.com/microsoftgraph/msgraph-sdk-dotnet-auth/issues).

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

# Additional resources

* NuGet Package: [https://www.nuget.org/packages/Microsoft.Graph.Auth](https://www.nuget.org/packages/Microsoft.Graph.Auth)


# License

Copyright (c) Microsoft Corporation. All Rights Reserved. Licensed under the MIT [license](LICENSE.txt). See [Third Party Notices](https://github.com/microsoftgraph/msgraph-sdk-dotnet/blob/master/THIRD%20PARTY%20NOTICES) for information on the packages referenced via NuGet.

