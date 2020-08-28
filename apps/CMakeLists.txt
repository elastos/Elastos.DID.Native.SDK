include(AddSubModule)

add_submodule(agent
    DIRECTORY agent
    DEPENDS libcrystal ela-did)
add_submodule(resolver
    DIRECTORY resolver
    DEPENDS libcrystal ela-did )
add_submodule(validater
    DIRECTORY validater
    DEPENDS ela-did)
