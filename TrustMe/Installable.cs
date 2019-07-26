using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace TrustMe {

    class Installable : UserControl {

        public static readonly DependencyProperty ValueProperty = DependencyProperty.Register(
            "Value",
            typeof(object),
            typeof(Installable),
            new FrameworkPropertyMetadata(OnValueChanged));

        public static readonly DependencyProperty InstallTextProperty = DependencyProperty.Register(
            "InstallText",
            typeof(string),
            typeof(Installable),
            new FrameworkPropertyMetadata(OnInstallTextChanged));

        public static readonly DependencyProperty CommandProperty = DependencyProperty.Register(
            "Command",
            typeof(ICommand),
            typeof(Installable),
            new FrameworkPropertyMetadata(OnCommandChanged));

        public static readonly DependencyProperty CommandParameterProperty = DependencyProperty.Register(
            "CommandParameter",
            typeof(object),
            typeof(Installable),
            new FrameworkPropertyMetadata(OnCommandParameterChanged));

        public object Value {
            get => GetValue(ValueProperty);
            set => SetValue(ValueProperty, value);
        }

        public string InstallText {
            get => (string)GetValue(InstallTextProperty);
            set => SetValue(InstallTextProperty, value);
        }

        public ICommand Command {
            get => (ICommand)GetValue(CommandProperty);
            set => SetValue(CommandProperty, value);
        }

        public object CommandParameter {
            get => GetValue(CommandParameterProperty);
            set => SetValue(CommandParameterProperty, value);
        }

        public Installable() {
            InstallButton = new Button();
            InstallText = "Install";
            OnValueChanged(this, new DependencyPropertyChangedEventArgs(ValueProperty, null, Value));
        }

        private static void OnValueChanged(DependencyObject d, DependencyPropertyChangedEventArgs e) {
            var control = d as Installable;
            var value = e.NewValue;
            if (value is string text && text != string.Empty) {
                control.TextBlock.Text = text;
                control.Content = control.TextBlock;
            }else control.Content = value ?? control.InstallButton;
        }

        private static void OnInstallTextChanged(DependencyObject d, DependencyPropertyChangedEventArgs e) {
            var control = d as Installable;
            var text = e.NewValue as string;
            control.InstallButton.Content = text;
        }


        private static void OnCommandChanged(DependencyObject d, DependencyPropertyChangedEventArgs e) {
            var control = d as Installable;
            var command = e.NewValue as ICommand;
            control.InstallButton.Command = command;
        }

        private static void OnCommandParameterChanged(DependencyObject d, DependencyPropertyChangedEventArgs e) {
            var control = d as Installable;
            var value = e.NewValue;
            control.InstallButton.CommandParameter = value;
        }

        private readonly Button InstallButton = new Button();
        private readonly TextBlock TextBlock = new TextBlock();

    }

}
