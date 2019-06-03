using Microsoft.Graph;
using Microsoft.Graph.Auth;
using Microsoft.Identity.Client;
using System.Collections.Generic;
using System.Threading.Tasks;
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
                                    .Build();


        var authProvider = new DeviceCodeProvider(clientApplication, scopes, HandleDeviceCodeMessage);
        
        var graphClient = new GraphServiceClient(authProvider);

        User profile = await graphClient.Me.Request().GetAsync();

        Username.Text = profile.DisplayName;
    }

    private async Task HandleDeviceCodeMessage(DeviceCodeResult result)
    {
        await this.Dispatcher.InvokeAsync(() =>
        {
            Username.Text = result.Message;
        });
    }
}