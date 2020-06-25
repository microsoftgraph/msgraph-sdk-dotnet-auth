# Microsoft Graph .NET Authentication Provider Library
[![Build status](https://o365exchange.visualstudio.com/O365%20Sandbox/_apis/build/status/Microsoft%20Graph/.Net/msgraph-sdk-dotnet-auth-build-and-packaging)](https://o365exchange.visualstudio.com/O365%20Sandbox/_build/latest?definitionId=2425)

Microsoft Graph .NET authentication library provides a set of OAuth scenario-centric authentication providers that implement `Microsoft.Graph.IAuthenticationProvider` and uses Microsoft Authentication Library (MSAL) under the hood to handle access token acquisition and storage. It also exposes `BaseRequest` extension methods that are used to set per request authentication options to the providers.

[Get started with Microsoft Graph .NET Authentication Provider Library](https://docs.microsoft.com/en-us/graph/sdks/choose-authentication-providers?tabs=CS) by integrating Microsoft Graph API into your .Net application.

Microsoft Graph .NET Authentication Provider Library targets .NetStandard 1.3 and depends on [Microsoft.Identity.Client 3.0.8](https://www.nuget.org/packages/Microsoft.Identity.Client/3.0.8).
# Installation via NuGet
To install the authentication provider library via Nuget:
- Search for `Microsoft.Graph.Auth` in NuGet as a prerelease package or
- Type `Install-Package Microsoft.Graph.Auth -PreRelease` into the Package Manager Console.
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
Are used by applications that can securely store an application's secret and call Microsoft Graph in the name of a user, or without a user. They are broadly classified as :
- Daemons/Services.
- Web Clients (Web Apps/ Web APIs).

#### a. Authorization code provider
Authorization code provider is used by Web Apps (ASP.NET & ASP.NET Core) to acquire Microsoft Graph access token in the name of a user.
It uses [MSALs Authorization Code](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/Acquiring-tokens-with-authorization-codes-on-web-apps) to authenticate Microsoft Graph requests.

```csharp
IConfidentialClientApplication confidentialClientApplication = ConfidentialClientApplicationBuilder
                .Create(clientId)
                .WithRedirectUri(redirectUri)
                .WithClientSecret(clientSecret) // or .WithCertificate(certificate)
                .Build();

AuthorizationCodeProvider authenticationProvider = new AuthorizationCodeProvider(confidentialClientApplication, scopes);
```

#### b. Client credential provider
Client credential provider is used by services and desktop applications to acquire Microsoft Graph access token without a user. The app should have previously registered a secret (app password or certificate) with Azure AD during the application registration.
This provider leverages on [MSALs Client Credential Flows](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/Client-credential-flows) to authenticate Microsoft Graph requests.

```csharp
IConfidentialClientApplication confidentialClientApplication = ConfidentialClientApplicationBuilder
                .Create(clientId)
                .WithTenantId(tenantID)
                .WithClientSecret(clientSecret)
                .Build();

ClientCredentialProvider authenticationProvider = new ClientCredentialProvider(confidentialClientApplication);
```

#### c. On behalf of provider
As the name suggests, on behalf of provider is used by services or daemons to acquire Microsoft Graph access token on behalf of a user by passing a UserAssertion.
This provider uses [MSALs On Behalf Of](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/on-behalf-of) to authenticate Microsoft Graph requests.

```csharp
IConfidentialClientApplication confidentialClientApplication = ConfidentialClientApplicationBuilder
                .Create(clientId)
                .WithRedirectUri(redirectUri)
                .WithClientSecret(clientSecret)
                .Build();

OnBehalfOfProvider authenticationProvider = new OnBehalfOfProvider(confidentialClientApplication, scopes);
```

### 2.2. Public Client Providers
These providers are used by Native client applications (mobile/ desktop applications) that can't securely store an application's secret and call Microsoft Graph in the name of a user.

#### a. Device code provider
Device code provider is used by desktop apps that run on devices without browsers to call Microsoft Graph in the name of a user.
This provider leverages [MSALs Device Code Flow](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/Device-Code-Flow) to authenticate Microsoft Graph requests.

```csharp
IPublicClientApplication publicClientApplication = PublicClientApplicationBuilder
                .Create(clientId)
                .Build();

DeviceCodeProvider authenticationProvider = new DeviceCodeProvider(publicClientApplication, scopes);
```

#### b. Integrated windows authentication provider
This provider is used by Windows hosted .NET applications running on computers joined to Azure AD to acquire token silently.
This provider leverages [MSALs Integrated Windows Authentication](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/Integrated-Windows-Authentication) to authenticate Microsoft Graph requests.

```csharp
IPublicClientApplication publicClientApplication = PublicClientApplicationBuilder
                .Create(clientId)
                .WithTenantId(tenantID)
                .Build();

IntegratedWindowsAuthenticationProvider authenticationProvider = new IntegratedWindowsAuthenticationProvider(publicClientApplication, scopes);
```

#### c. Interactive authentication provider
Interactive authentication provider is used by mobile applications (Xamarin and UWP) and desktops applications to call Microsoft Graph in the name of a user.
Refer to [MSALs interactive Authentication](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/Acquiring-tokens-interactively) on how to configure the provider for your platform of choice since each platform has its own specificities.

```csharp
IPublicClientApplication publicClientApplication = PublicClientApplicationBuilder
                .Create(clientId)
                .Build();

InteractiveAuthenticationProvider authenticationProvider = new InteractiveAuthenticationProvider(publicClientApplication, scopes);
```

#### d. Username password provider
This provider is used by desktop applications to acquire Microsoft Graph access token by leveraging [MSALs Username Password](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/Username-Password-Authentication) with the provider username (email) and password.

```csharp
IPublicClientApplication publicClientApplication = PublicClientApplicationBuilder
                .Create(clientId)
                .WithTenantId(tenantID)
                .Build();

UsernamePasswordProvider authenticationProvider = new UsernamePasswordProvider(publicClientApplication, scopes);
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
// Create a client application.
IConfidentialClientApplication confidentialClientApplication = ConfidentialClientApplicationBuilder
                .Create(clientId)
                .WithTenantId(tenantID)
                .WithClientSecret(clientSecret)
                .Build();
// Create an authentication provider.
ClientCredentialProvider authenticationProvider = new ClientCredentialProvider(confidentialClientApplication);
// Configure GraphServiceClient with provider.
GraphServiceClient graphServiceClient = new GraphServiceClient(authenticationProvider);
// Make a request
var me = await graphServiceClient.Me.Request().WithForceRefresh(true).GetAsync();
```

## 2. On behalf of provider

```csharp
// Create a client application.
IConfidentialClientApplication confidentialClientApplication = ConfidentialClientApplicationBuilder
                .Create(clientId)
                .WithTenantId(tenantID)
                //the Authority is a required parameter when your application is configured to accept authentications only from the tenant where it is registered
                .WithAuthority(authority)
                .WithClientSecret(clientSecret)
                .Build();
                
//use the API reference to determine which scopes are appropriate for your API request
// e.g. - https://docs.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0&tabs=http
var scopes = new string[] { "User.Read" };
// Create an authentication provider.
ClientCredentialProvider authenticationProvider = new OnBehalfOfProvider(confidentialClientApplication);

var jsonWebToken = actionContext.Request.Headers.Authorization.Parameter;
var userAssertion = new UserAssertion(jsonWebToken);
// Configure GraphServiceClient with provider.
GraphServiceClient graphServiceClient = new GraphServiceClient(authenticationProvider);
// Make a request
var me = await graphServiceClient.Me.Request().WithUserAssertion(userAssertion).WithForceRefresh(true).GetAsync();
```

# Documentation
* MSAL .Net [authentication scenarios](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/scenarios).
* For documentations on provider arguments, refer to [MSAL documentation](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/Scenarios#public-client-and-confidential-client-applications).

# Issues
To view or log [MSAL.Net](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki) issues, see [issues](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/issues).
This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

To view or log Microsoft Graph Authentication library issues, see [issues](https://github.com/microsoftgraph/msgraph-sdk-dotnet-auth/issues).

# Additional resources
* NuGet Package: [https://www.nuget.org/packages/Microsoft.Graph.Auth](https://www.nuget.org/packages/Microsoft.Graph.Auth)

# License
Copyright (c) Microsoft Corporation. All Rights Reserved. Licensed under the MIT [license](LICENSE.txt). See [Third Party Notices](https://github.com/microsoftgraph/msgraph-sdk-dotnet/blob/master/THIRD%20PARTY%20NOTICES) for information on the packages referenced via NuGet.
