use bitcoin::node::Node;

fn main() -> std::io::Result<()> {
    let node: Node = Node{};

    node.start().unwrap();

    Ok(())
}
