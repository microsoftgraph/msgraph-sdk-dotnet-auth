using Microsoft.Graph;
using Microsoft.Graph.Auth;
using Microsoft.Identity.Client;
using System.Collections.Generic;
using System.Windows;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        Login();
    }

    public async void Login()
    {
        string clientId = "<client-id-guid>";
        List<string> scopes = new List<string> { "User.ReadBasic.All" };

        var clientApplication = PublicClientApplicationBuilder
                                    .Create(clientId)
                                    .WithAuthority(AzureCloudInstance.AzurePublic, AadAuthorityAudience.AzureAdMultipleOrgs)
                                    .WithRedirectUri("https://login.microsoftonline.com/common/oauth2/nativeclient")
                                    .Build();

        var authProvider = new InteractiveAuthenticationProvider(clientApplication, scopes);

        var graphClient = new GraphServiceClient(authProvider);

        User profile = await graphClient.Me.Request().GetAsync();

        Username.Text = profile.UserPrincipalName;
    }
}