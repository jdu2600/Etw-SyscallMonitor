namespace SyscallSummariser
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Threading;
    using System.Timers;
    using System.Windows;
    using System.Windows.Controls;
    using System.Windows.Documents;
    using System.Windows.Media;

    static class KeyValuePairExtensions
    {
        public static void Deconstruct<K, V>(this KeyValuePair<K, V> kvp, out K key, out V value)
        {
            key = kvp.Key;
            value = kvp.Value;
        }
    }

    /// <summary>
    /// Interaction logic for DebugWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly Paragraph paragraph = new Paragraph();

        public MainWindow()
        {
            InitializeComponent();
            logWindow.Document.Blocks.Add(paragraph);
            Closing += OnWindowClosing;
            throttleTimer = new System.Timers.Timer(600);
            throttleTimer.AutoReset = false;
            throttleTimer.Elapsed += (s, e) => {
                this.Dispatcher.BeginInvoke(new Action(() =>
                {
                    foreach (TreeViewItem item in treeView.Items)
                    {
                        FilterItem(item, filterBox.Text);
                    }
                }));
            };
        }

        public void AddTreeView(Dictionary<string, Dictionary<string, SortedSet<string>>> summaries)
        {
            this.Dispatcher.BeginInvoke(new Action(() =>
            {
                // traitshash: { feature: set(observed values) }
                lock (summaries)
                {
                    treeView.Items.Clear();
                    foreach (var (traitshash, features) in summaries)
                    {
                        if (!features.ContainsKey("Syscalls"))
                            continue;
                        
                        var tvi = new TreeViewItem()
                        {
                            Header = traitshash,
                            IsTextSearchEnabled = true,
                            IsTextSearchCaseSensitive = false
                        };
                        foreach (var (feature, list) in features)
                        {
                            if (feature == "ProcessCreationTraitsHash")
                                continue;
                            var tvi2 = new TreeViewItem()
                            {
                                Header = feature,
                                IsTextSearchEnabled = true,
                                IsTextSearchCaseSensitive = false
                            };
                            foreach (var item in list)
                            {
                                var tvi3 = new TreeViewItem()
                                {
                                    Header = item,
                                    IsTextSearchEnabled = true,
                                    IsTextSearchCaseSensitive = false
                                };
                                tvi2.Items.Add(tvi3);

                            }
                            tvi.Items.Add(tvi2);
                        }
                        treeView.Items.Add(tvi);
                    }
                }

                foreach (TreeViewItem item in treeView.Items)
                {
                    FilterItem(item, filterBox.Text);
                }
            }));
        }

        private System.Timers.Timer throttleTimer;
        public void FilterText(object sender, TextChangedEventArgs e)
        {

            if(!throttleTimer.Enabled)
            {
                throttleTimer.Start();
            }
            else
            {
                throttleTimer.Stop();
                throttleTimer.Start();
            }
        }

        private Visibility FilterItem(TreeViewItem item, string keyword)
        {
            if (keyword.Length == 0)
            {
                item.Background = Brushes.White;
                item.Visibility = Visibility.Visible;
                foreach (TreeViewItem child in item.Items)
                {
                    var _ = FilterItem(child, keyword);
                }
            }

            else if (item.Header.ToString().IndexOf(keyword, 0, StringComparison.OrdinalIgnoreCase) != -1)
            {
                item.Background = Brushes.Yellow;
                item.Visibility = Visibility.Visible;
                item.IsExpanded = false;
            }
            else
            {
                item.Background = Brushes.White;
                item.IsExpanded = false;
                item.Visibility = Visibility.Collapsed;

                if (item.Items.IsEmpty)
                {
                    item.Visibility = Visibility.Collapsed;
                }
                else
                {
                    item.Visibility = Visibility.Collapsed;
                    foreach (TreeViewItem child in item.Items)
                    {
                        if (Visibility.Visible == FilterItem(child, keyword))
                        {
                            item.Visibility = Visibility.Visible;
                            item.IsExpanded = true;
                        }
                    }

                    PropagateVisible(item);
                }
            }

            return item.Visibility;
        }

        private void PropagateVisible(TreeViewItem item)
        {
            if (item.Visibility != Visibility.Visible)
                return;
            
            foreach (TreeViewItem child in item.Items)
            {
                child.Visibility = Visibility.Visible;
                PropagateVisible(child);
            }
        }

        public void AddLine(string message, Brush colour)
        {
            paragraph.Inlines.Add(new Span(new Run(message)) { Foreground = colour });
            paragraph.Inlines.Add(new LineBreak());
            logWindow.ScrollToEnd();
        }
        public void OnWindowClosing(object sender, CancelEventArgs e)
        {
            Log.Write("Window closed - stopping");
            Program.Stop();
        }
    }
}
