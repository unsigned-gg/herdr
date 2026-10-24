// Copyright (c) Meta Platforms, Inc. and affiliates.
// Dual-licensed under MIT OR Apache-2.0 (from facebookexperimental/rust-shed).

//! Macro for borrowing variables into local bindings before a closure or async block.

/// Borrow a list of variables (or struct fields) into local references.
#[macro_export]
macro_rules! borrowed {
    ($i:ident as $alias:ident : $borrow:ty) => {
        let $alias: $borrow = {
            use ::std::borrow::Borrow;
            $i.borrow()
        };
    };
    ($i:ident as $alias:ident) => {
        let $alias = {
            use ::std::borrow::Borrow;
            $i.borrow()
        };
    };
    (mut $i:ident as $alias:ident : $borrow:ty) => {
        let mut $alias: $borrow = {
            use ::std::borrow::Borrow;
            $i.borrow()
        };
    };
    (mut $i:ident as $alias:ident) => {
        let mut $alias = {
            use ::std::borrow::Borrow;
            $i.borrow()
        };
    };
    ($i:ident as $alias:ident : $borrow:ty, $($tt:tt)*) => {
        $crate::borrowed!($i as $alias: $borrow);
        $crate::borrowed!($($tt)*);
    };
    ($i:ident as $alias:ident, $($tt:tt)*) => {
        $crate::borrowed!($i as $alias);
        $crate::borrowed!($($tt)*);
    };
    (mut $i:ident as $alias:ident : $borrow:ty, $($tt:tt)*) => {
        $crate::borrowed!(mut $i as $alias: $borrow);
        $crate::borrowed!($($tt)*);
    };
    (mut $i:ident as $alias:ident, $($tt:tt)*) => {
        $crate::borrowed!(mut $i as $alias);
        $crate::borrowed!($($tt)*);
    };
    ($this:ident . $i:ident as $alias:ident) => {
        let $alias = {
            use ::std::borrow::Borrow;
            $this.$i.borrow()
        };
    };
    ($this:ident . $i:ident as $alias:ident : $borrow:ty) => {
        let $alias: $borrow = {
            use ::std::borrow::Borrow;
            $this.$i.borrow()
        };
    };
    (mut $this:ident . $i:ident as $alias:ident : $borrow:ty) => {
        let mut $alias: $borrow = {
            use ::std::borrow::Borrow;
            $this.$i.borrow()
        };
    };
    (mut $this:ident . $i:ident as $alias:ident) => {
        let mut $alias = {
            use ::std::borrow::Borrow;
            $this.$i.borrow()
        };
    };
    ($this:ident . $i:ident as $alias:ident : $borrow:ty, $($tt:tt)*) => {
        $crate::borrowed!($this . $i as $alias: $borrow);
        $crate::borrowed!($($tt)*);
    };
    ($this:ident . $i:ident as $alias:ident, $($tt:tt)*) => {
        $crate::borrowed!($this . $i as $alias);
        $crate::borrowed!($($tt)*);
    };
    (mut $this:ident . $i:ident as $alias:ident : $borrow:ty, $($tt:tt)*) => {
        $crate::borrowed!(mut $this . $i as $alias: $borrow);
        $crate::borrowed!($($tt)*);
    };
    (mut $this:ident . $i:ident as $alias:ident, $($tt:tt)*) => {
        $crate::borrowed!(mut $this . $i as $alias);
        $crate::borrowed!($($tt)*);
    };
    ($i:ident : $borrow:ty) => {
        $crate::borrowed!($i as $i: $borrow)
    };
    ($i:ident) => {
        $crate::borrowed!($i as $i)
    };
    (mut $i:ident : $borrow:ty) => {
        $crate::borrowed!(mut $i as $i: $borrow)
    };
    (mut $i:ident) => {
        $crate::borrowed!(mut $i as $i)
    };
    ($i:ident : $borrow:ty, $($tt:tt)*) => {
        $crate::borrowed!($i as $i: $borrow);
        $crate::borrowed!($($tt)*);
    };
    ($i:ident, $($tt:tt)*) => {
        $crate::borrowed!($i as $i);
        $crate::borrowed!($($tt)*);
    };
    (mut $i:ident, $($tt:tt)*) => {
        $crate::borrowed!(mut $i);
        $crate::borrowed!($($tt)*);
    };
    ($this:ident . $i:ident : $borrow:ty) => {
        $crate::borrowed!($this.$i as $i: $borrow)
    };
    ($this:ident . $i:ident) => {
        $crate::borrowed!($this.$i as $i)
    };
    (mut $this:ident . $i:ident : $borrow:ty) => {
        let mut $i: $borrow = {
            use ::std::borrow::Borrow;
            $this.$i.borrow()
        };
    };
    (mut $this:ident . $i:ident) => {
        let mut $i = {
            use ::std::borrow::Borrow;
            $this.$i.borrow()
        };
    };
    ($this:ident . $i:ident : $borrow:ty, $($tt:tt)*) => {
        $crate::borrowed!($this . $i as $i: $borrow);
        $crate::borrowed!($($tt)*);
    };
    ($this:ident . $i:ident, $($tt:tt)*) => {
        $crate::borrowed!($this . $i as $i);
        $crate::borrowed!($($tt)*);
    };
    (mut $this:ident . $i:ident : $borrow:ty, $($tt:tt)*) => {
        $crate::borrowed!(mut $this . $i: $borrow);
        $crate::borrowed!($($tt)*);
    };
    (mut $this:ident . $i:ident, $($tt:tt)*) => {
        $crate::borrowed!(mut $this . $i);
        $crate::borrowed!($($tt)*);
    };
    () => {};
}

pub use borrowed;

#[cfg(test)]
mod tests {
    struct A {
        x: String,
    }

    #[test]
    fn borrowed_basic_and_typed() {
        let a = A { x: "hello".to_owned() };
        let y = "world".to_owned();
        borrowed!(a.x: &str, y as y_ref: &str,);
        assert_eq!(format!("{x} {y_ref}"), "hello world");
    }
}
