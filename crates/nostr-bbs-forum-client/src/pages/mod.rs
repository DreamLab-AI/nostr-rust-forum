//! Page components for the forum routes.

// -- Existing pages -----------------------------------------------------------
mod admin;
mod channel;
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
mod glossary;
mod governance;
mod note_view;
mod pod_browser;
mod profile;
mod section;
mod settings;
mod setup;
mod thread;

// -- Re-exports ---------------------------------------------------------------
pub use admin::AdminPage;
pub use category::CategoryPage;
pub use channel::ChannelPage;
pub use connect::ConnectPage;
pub use dm_chat::DmChatPage;
pub use dm_list::DmListPage;
pub use events::EventsPage;
pub use forums::ForumsPage;
pub use glossary::GlossaryPage;
pub use governance::GovernancePage;
pub use home::HomePage;
pub use login::LoginPage;
pub use note_view::NoteViewPage;
pub use pod_browser::PodBrowserPage;
pub use profile::ProfilePage;
pub use section::SectionPage;
pub use settings::SettingsPage;
pub use setup::SetupPage;
pub use signup::SignupPage;
pub use thread::ThreadPage;
