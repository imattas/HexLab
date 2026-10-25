#pragma once
#include "hexlab/workspace/document.hpp"
#include "hexlab/loaders/recipe.hpp"
namespace hexlab {
// Performs bounded profile file I/O. Call from the opening worker, never a GUI
// event handler. Flat options and external profile intent are mutually exclusive.
HEXLAB_WORKSPACE_EXPORT Result<LoadRecipe> resolve_open_recipe(const OpenRequest &, std::stop_token);
} // namespace hexlab
