//! Page components for the forum routes.

// -- Existing pages -----------------------------------------------------------
mod admin;
mod channel;
mod chat;
mod dm_chat;
mod dm_list;
mod home;
mod login;
mod signup;

// -- New pages (v3.0 feature parity) -----------------------------------------
mod category;
mod events;
mod forums;
mod note_view;
mod pending;
mod profile;
mod search;
mod section;
mod settings;
mod setup;

// -- Re-exports ---------------------------------------------------------------
pub use admin::AdminPage;
pub use category::CategoryPage;
pub use channel::ChannelPage;
pub use chat::ChatPage;
pub use dm_chat::DmChatPage;
pub use dm_list::DmListPage;
pub use events::EventsPage;
pub use forums::ForumsPage;
pub use home::HomePage;
pub use login::LoginPage;
pub use note_view::NoteViewPage;
pub use pending::PendingPage;
pub use profile::ProfilePage;
pub use search::SearchPage;
pub use section::SectionPage;
pub use settings::SettingsPage;
pub use setup::SetupPage;
pub use signup::SignupPage;
