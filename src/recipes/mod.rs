//! Strict, data-only Bridgefu Recipe packages.
//!
//! Recipe packages describe supported transport bridges and their deployment
//! assets. They never load executable code into the Bridgefu process. The
//! compiler resolves whole-node typed inputs, validates the resulting bridge
//! graph, and produces a deterministic non-secret revision fingerprint.

mod catalog;
mod compiler;
mod manifest;

pub use catalog::{RecipeCatalog, RecipePackage, RecipeSelector, RecipeSource};
pub use compiler::{CompiledRecipe, RecipeCompiler, RecipeError};
pub use manifest::{
    AmazonConnectMedia, RecipeAudioCodec, RecipeBridgeSpec, RecipeCorrelationSpec,
    RecipeEndpointSpec, RecipeInputDefinition, RecipeInputType, RecipeManifest, RecipeMetadata,
    RecipeSelection, RecipeSipAuthSpec, RecipeSpec, RecipeSupport, SipAdmissionMode,
    SipAdmissionSpec, SipSecurity, BUILTIN_RECIPE_API_VERSION, BUILTIN_RECIPE_KIND,
};
