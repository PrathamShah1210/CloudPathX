import * as React from 'react';
import {Slot} from '@radix-ui/react-slot';
import {cva} from 'class-variance-authority';
import type {VariantProps} from 'class-variance-authority';
import {cn} from '../../lib/utils';
// Local shadcn/ui-style primitive: the application owns styles and behavior.
const buttonVariants=cva('inline-flex items-center justify-center gap-2 rounded-md font-medium disabled:pointer-events-none disabled:opacity-50',{variants:{variant:{default:'primary',secondary:'secondary',ghost:'icon-button'}},defaultVariants:{variant:'default'}});
type Props=React.ComponentProps<'button'>&VariantProps<typeof buttonVariants>&{asChild?:boolean};
const Button=React.forwardRef<HTMLButtonElement,Props>(({className,variant,asChild=false,...props},ref)=>{const Comp=asChild?Slot:'button';return <Comp className={cn(buttonVariants({variant,className}))} ref={ref} {...props}/>;});
Button.displayName='Button';
export {Button,buttonVariants};
