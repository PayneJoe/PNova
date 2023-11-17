pub mod circuit;
pub mod errors;
pub mod nifs;
pub mod plonk;

#[cfg(test)]
mod tests {

    #[test]
    fn test_add() {
        assert_eq!(2, 1 + 1);
    }
}
