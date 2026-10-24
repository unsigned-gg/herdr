// Copyright (c) Meta Platforms, Inc. and affiliates.
// Dual-licensed under MIT OR Apache-2.0 (from facebookexperimental/rust-shed).

//! Macro for cloning variables before moving them into a closure or async block.

/// Clone a list of variables (or struct fields) into local bindings before a `move` closure/block.
#[macro_export]
macro_rules! cloned {
    ($i:ident as $alias:ident) => {
        let $alias = $i.clone();
    };
    (mut $i:ident as $alias:ident) => {
        let mut $alias = $i.clone();
    };
    ($i:ident as $alias:ident, $($tt:tt)*) => {
        $crate::cloned!($i as $alias);
        $crate::cloned!($($tt)*);
    };
    (mut $i:ident as $alias:ident, $($tt:tt)*) => {
        $crate::cloned!(mut $i as $alias);
        $crate::cloned!($($tt)*);
    };
    ($this:ident . $i:ident as $alias:ident) => {
        let $alias = $this.$i.clone();
    };
    (mut $this:ident . $i:ident as $alias:ident) => {
        let mut $alias = $this.$i.clone();
    };
    ($this:ident . $i:ident as $alias:ident, $($tt:tt)*) => {
        $crate::cloned!($this . $i as $alias);
        $crate::cloned!($($tt)*);
    };
    (mut $this:ident . $i:ident as $alias:ident, $($tt:tt)*) => {
        $crate::cloned!(mut $this . $i as $alias);
        $crate::cloned!($($tt)*);
    };
    ($i:ident) => {
        $crate::cloned!($i as $i)
    };
    (mut $i:ident) => {
        $crate::cloned!(mut $i as $i)
    };
    ($i:ident, $($tt:tt)*) => {
        $crate::cloned!($i as $i);
        $crate::cloned!($($tt)*);
    };
    (mut $i:ident, $($tt:tt)*) => {
        $crate::cloned!(mut $i);
        $crate::cloned!($($tt)*);
    };
    ($this:ident . $i:ident) => {
        $crate::cloned!($this.$i as $i)
    };
    (mut $this:ident . $i:ident) => {
        let mut $i = $this.$i.clone();
    };
    ($this:ident . $i:ident, $($tt:tt)*) => {
        $crate::cloned!($this . $i as $i);
        $crate::cloned!($($tt)*);
    };
    (mut $this:ident . $i:ident, $($tt:tt)*) => {
        $crate::cloned!(mut $this . $i);
        $crate::cloned!($($tt)*);
    };
    () => {};
}

pub use cloned;

#[cfg(test)]
mod tests {
    struct A {
        x: String,
    }

    #[test]
    fn cloned_basic_and_alias() {
        let a = A { x: "shed".to_owned() };
        let b = 42_u32;
        cloned!(a.x, b as b_copy, mut b as b_mut,);
        b_mut += 1;
        assert_eq!(x, "shed");
        assert_eq!(b_copy, 42);
        assert_eq!(b_mut, 43);
    }
}
