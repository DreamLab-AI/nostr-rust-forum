//! Page components for the forum routes.

// -- Existing pages -----------------------------------------------------------
mod admin;
mod channel;
mod chat;
mod connect;
mod dm_chat;
mod dm_list;
mod home;
mod login;
mod signup;

// -- New pages (v3.0 feature parity) -----------------------------------------
mod category;
mod events;
mod forums;
mod governance;
mod marketplace;
mod note_view;
mod pending;
mod pod_browser;
mod profile;
mod search;
mod section;
mod settings;
mod setup;
mod thread;

// -- Re-exports ---------------------------------------------------------------
pub use admin::AdminPage;
pub use category::CategoryPage;
pub use channel::ChannelPage;
pub use chat::ChatPage;
pub use connect::ConnectPage;
pub use dm_chat::DmChatPage;
pub use dm_list::DmListPage;
pub use events::EventsPage;
pub use forums::ForumsPage;
pub use governance::GovernancePage;
pub use home::HomePage;
pub use login::LoginPage;
pub use marketplace::MarketplacePage;
pub use note_view::NoteViewPage;
pub use pending::PendingPage;
pub use pod_browser::PodBrowserPage;
pub use profile::ProfilePage;
pub use search::SearchPage;
pub use section::SectionPage;
pub use settings::SettingsPage;
pub use setup::SetupPage;
pub use signup::SignupPage;
pub use thread::ThreadPage;
