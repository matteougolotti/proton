use bitcoin::node::Node;

fn main() -> std::io::Result<()> {
    let node: Node = Node::new();

    node.start().unwrap();

    Ok(())
}
