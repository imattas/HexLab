hexlab_add_library(workspace SOURCES src/document.cpp src/open_recipe.cpp src/workspace.cpp src/navigation.cpp src/jobs.cpp src/listing.cpp
  src/commands.cpp src/command_validation.cpp src/action_availability.cpp src/project.cpp src/presentation.cpp src/export.cpp src/analysis_pool.cpp src/project_analysis.cpp src/project_graph.cpp src/project_actor.cpp src/project_exchange.cpp src/search.cpp src/document_manager.cpp src/debug_variables.cpp
  DEPENDS hexlab::loaders hexlab::analysis hexlab::database hexlab::types hexlab::symbols)
if(WIN32)
  target_link_libraries(hexlab_workspace PRIVATE bcrypt)
endif()
if(BUILD_TESTING)
  target_sources(hexlab_workspace PRIVATE src/project_testing.cpp)
  target_compile_definitions(hexlab_workspace PRIVATE HEXLAB_WORKSPACE_TESTING)
endif()
