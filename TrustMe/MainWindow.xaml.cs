using System;
using System.Windows;

namespace TrustMe {

    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window {

        /// <summary>
        /// Loads XAML.
        /// </summary>
        public MainWindow() => InitializeComponent();

        /// <summary>
        /// Fixes the minimal height when the automatic sizing completes for the first time.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Window_ContentRendered(object sender, EventArgs e) => MinHeight = ActualHeight;
    }

}