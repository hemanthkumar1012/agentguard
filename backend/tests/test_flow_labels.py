from app.flow.labels import PUBLIC, DestinationRegistry, ManifestRegistry, ToolManifest, Capability, flows_to, meet


def fs(*items):
    return frozenset(items)


def test_no_private_data_flows_anywhere():
    assert flows_to(None, fs(PUBLIC))


def test_private_data_never_flows_to_a_public_audience():
    assert not flows_to(fs("internal", "domain:acme.com"), fs(PUBLIC))


def test_domain_reader_covers_every_address_in_that_domain():
    readers = fs("domain:acme.com")
    assert flows_to(readers, fs("user:priya@acme.com"))
    assert not flows_to(readers, fs("user:priya@acme.com.evil.io"))
    assert not flows_to(readers, fs("user:priya@acme.com", "user:x@gmail.com"))


def test_reading_more_private_data_only_shrinks_the_reader_set():
    alice = fs("internal", "user:alice@x.com")
    bob = fs("internal", "user:bob@x.com")
    assert meet(None, alice) == alice
    assert meet(alice, bob) == fs("internal")
    assert meet(fs("domain:acme.com"), fs("user:priya@acme.com")) == fs("user:priya@acme.com")
    assert meet(fs(PUBLIC), alice) == alice


def test_destination_audience_resolution():
    destinations = DestinationRegistry()
    destinations.register("slack:#support-*", {"domain:acme.com"})
    assert destinations.audience("slack:#support-escalations") == fs("domain:acme.com")
    assert destinations.audience("Priya@Gmail.com") == fs("user:priya@gmail.com")
    assert destinations.audience("https://paste.example.net/new") == fs(PUBLIC)


def test_manifest_lookup_falls_back_and_unknown_tools_get_the_worst_case():
    registry = ManifestRegistry([
        ToolManifest("*", "send_email", fs(Capability.EGRESS), destination_field="to"),
        ToolManifest("crm", "*", fs(Capability.READS_PRIVATE)),
    ])
    assert registry.resolve("gmail", "send_email").destination_field == "to"
    assert registry.resolve("crm", "lookup").has(Capability.READS_PRIVATE)
    unknown = registry.resolve("mystery", "do_thing")
    assert not unknown.known
    assert unknown.has(Capability.EGRESS) and unknown.has(Capability.INGESTS_UNTRUSTED)
    assert not unknown.has(Capability.READS_PRIVATE)
